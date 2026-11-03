package rules

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"slices"

	"golang.org/x/tools/go/analysis"
)

var DMAnalyzer = &analysis.Analyzer{
	Name: "dm",
	Doc:  "direct media rules (DM001-DM002): Download must map upstream failures to RespErrors, since the media proxy sends any other error as 404",
	Run:  runDM,

	Requires:  []*analysis.Analyzer{NetAnalyzer},
	FactTypes: []analysis.Fact{new(dmErrFact)},
}

func runDM(pass *analysis.Pass) (any, error) {
	if len(pass.Files) == 0 {
		return nil, nil
	}
	if err := ConfigError(pass); err != nil {
		return nil, err
	}
	pi := infoFor(pass)
	ef := newErrFlow(pass, pi, ConfigFor(pass)).forDirectMedia().withFacts(pass, newDMFact)
	if !pi.isBridge {
		return nil, nil
	}
	proxied := "the media proxy sends it as 404, so clients treat the media as gone"
	if !ef.transportMapped {
		proxied = "the pinned mautrix (before v0.32.0) sends every error that isn't a mautrix.RespError as 404, transport errors included, so clients treat the media as gone"
	}
	for _, fd := range pi.funcsWithScope(ScopeDirectMedia) {
		idx := errorResultIndex(funcType(pass.TypesInfo, fd))
		if idx < 0 {
			continue
		}
		ef.returnedErrors(fd, idx, func(ret *ast.ReturnStmt, o errOrigin) {
			switch {
			case o.kind == errRaw || o.kind == errConstructed && o.hasCallee():
				report(pass, ret, DM001, fmt.Sprintf("Download returns %s, and %s; map upstream failures to a mautrix.RespError with a matching status", describeOrigin(pass.Fset, o), proxied))
			case o.kind == errUnrecognised:
				proxy := "the media proxy"
				if o.calleePkgName() == "bridgev2" {
					proxy = "the pinned mautrix (before v0.32.0)"
				}
				report(pass, ret, DM001, fmt.Sprintf("Download returns %s, which %s doesn't recognise as a RespError, so it sends it as 404; return a mautrix.RespError value", describeOrigin(pass.Fset, o), proxy))
			case o.kind == errConstructed && o.formatsStatus:
				report(pass, ret, DM002, fmt.Sprintf("Download returns %s built from an upstream status, which the media proxy sends as 404 whatever the status was; return a mautrix.RespError with a matching status", describeOrigin(pass.Fset, o)))
			}
		})
	}
	return nil, nil
}

// isHTTPClientCall matches a request sent through an HTTP client: Get, Head, Post and PostForm, as
// functions or Client methods, and Client.Do, in net/http or a fork like fhttp. Every error they return
// is a *url.Error, which exhttp.IsNetworkError recognises.
func isHTTPClientCall(f *types.Func) bool {
	switch f.Name() {
	case "Do", "Get", "Head", "Post", "PostForm":
	default:
		return false
	}
	if f.Pkg() == nil || !isHTTPPackage(f.Pkg()) {
		return false
	}
	sig := f.Type().(*types.Signature)
	if sig.Recv() == nil {
		return f.Name() != "Do"
	}
	return isConcreteMethod(f) && recvTypeName(sig) == "Client"
}

// isHTTPPackage reports whether pkg is net/http or a fork of it, with Request and Response types that
// have net/http's fields.
func isHTTPPackage(pkg *types.Package) bool {
	if pkg.Path() == "net/http" {
		return true
	}
	req, _ := pkg.Scope().Lookup("Request").(*types.TypeName)
	resp, _ := pkg.Scope().Lookup("Response").(*types.TypeName)
	return req != nil && resp != nil && isHTTPStruct(req.Type(), "Request") && isHTTPStruct(resp.Type(), "Response")
}

// libErrorType returns the type of t when it's a network library's own error type, like a typed HTTP
// status error: one declared in a network library that isn't a bridge package or the standard library.
func (ef *errFlow) libErrorType(t types.Type) *types.TypeName {
	if !ef.directMedia || !isErrorType(t) || isRespErrorType(t) {
		return nil
	}
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := types.Unalias(t).(*types.Named)
	if !ok || named.Obj().Pkg() == nil {
		return nil
	}
	pkg := named.Obj().Pkg()
	if notFollowed(pkg.Path()) || ef.isBridgePkg(pkg) || !ef.net.pkgReaches(pkg) {
		return nil
	}
	return named.Obj()
}

func (ef *errFlow) isBridgePkg(pkg *types.Package) bool {
	if pkg == ef.pi.pass.Pkg {
		return ef.pi.isBridge
	}
	for _, imp := range pkg.Imports() {
		if imp.Path() == pathBridgev2 {
			return true
		}
	}
	return false
}

// typeCheck matches a condition, with the init statement of its if or switch, that checks the error
// being classified for a library error type. ok is unset for a check made before the error was last
// assigned, which says nothing about the value used.
type typeCheck func(cond ast.Expr, init ast.Stmt) (negated, ok bool)

// ruledOutLibType reports whether use, a use of the error v last assigned at assigned, is where the
// function already knows v isn't the library error type it checked for: in the branch or switch case
// that only runs when the check didn't match, or after a check whose matching branch returns.
func (ef *errFlow) ruledOutLibType(fn ast.Node, use ast.Node, v types.Object, assigned token.Pos) bool {
	check := func(cond ast.Expr, init ast.Stmt) (negated, ok bool) {
		found, negated := ef.libTypeCheck(cond, init, v)
		return negated, found != nil && found.Pos() > assigned
	}
	caseCheck := func(sw *ast.TypeSwitchStmt, cc *ast.CaseClause) bool {
		return sw.Pos() > assigned && ef.typeSwitchOn(sw, v) && ef.listsLibType(cc)
	}
	var prev ast.Node = use
	for p := ef.pi.parents[use]; p != nil && p != fn; prev, p = p, ef.pi.parents[p] {
		switch s := p.(type) {
		case *ast.IfStmt:
			if negated, ok := check(s.Cond, s.Init); ok && (prev == s.Body && negated || prev == s.Else && !negated) {
				return true
			}
		case *ast.CaseClause:
			if ef.caseRulesOut(s, prev, check) || ef.typeCaseRulesOut(s, prev, caseCheck) {
				return true
			}
		}
		for _, st := range stmtList(p) {
			if st == prev {
				break
			}
			if returnsWhenMatched(st, check, caseCheck) {
				return true
			}
		}
	}
	return false
}

// caseRulesOut reports whether prev, a statement in cc, only runs when the check didn't match: cc is a
// case of a tagless switch that is a negated check, or an earlier case (any other, for default) is a
// check and doesn't fall through. Cases don't fall through otherwise, so reaching cc means it was false.
func (ef *errFlow) caseRulesOut(cc *ast.CaseClause, prev ast.Node, check typeCheck) bool {
	st, isStmt := prev.(ast.Stmt)
	body, _ := ef.pi.parents[cc].(*ast.BlockStmt)
	if !isStmt || body == nil || !slices.Contains(cc.Body, st) {
		return false
	}
	sw, _ := ef.pi.parents[body].(*ast.SwitchStmt)
	if sw == nil || sw.Tag != nil {
		return false
	}
	if len(cc.List) == 1 {
		if negated, ok := check(cc.List[0], sw.Init); ok && negated {
			return true
		}
	}
	for _, c := range sw.Body.List {
		other := c.(*ast.CaseClause)
		if other == cc {
			if cc.List != nil {
				break
			}
			continue
		}
		if !endsInFallthrough(other.Body) && matchesCase(other, sw.Init, check) {
			return true
		}
	}
	return false
}

// typeCaseRulesOut is caseRulesOut for a type switch on the error: an earlier case (any other, for
// default) lists the library error type, and type switch cases can't fall through.
func (ef *errFlow) typeCaseRulesOut(cc *ast.CaseClause, prev ast.Node, caseCheck typeCaseCheck) bool {
	st, isStmt := prev.(ast.Stmt)
	body, _ := ef.pi.parents[cc].(*ast.BlockStmt)
	if !isStmt || body == nil || !slices.Contains(cc.Body, st) {
		return false
	}
	sw, _ := ef.pi.parents[body].(*ast.TypeSwitchStmt)
	if sw == nil {
		return false
	}
	for _, c := range sw.Body.List {
		other := c.(*ast.CaseClause)
		if other == cc {
			if cc.List != nil {
				break
			}
			continue
		}
		if caseCheck(sw, other) {
			return true
		}
	}
	return false
}

// typeCaseCheck reports whether cc, a case of sw, lists the library error type for the error being
// classified, in a type switch on that error made after it was last assigned.
type typeCaseCheck func(sw *ast.TypeSwitchStmt, cc *ast.CaseClause) bool

// typeSwitchOn reports whether sw switches on v's type: `switch v.(type)` or `switch x := v.(type)`.
func (ef *errFlow) typeSwitchOn(sw *ast.TypeSwitchStmt, v types.Object) bool {
	var x ast.Expr
	switch a := sw.Assign.(type) {
	case *ast.ExprStmt:
		x = a.X
	case *ast.AssignStmt:
		if len(a.Rhs) == 1 {
			x = a.Rhs[0]
		}
	}
	ta, ok := unparen(x).(*ast.TypeAssertExpr)
	if !ok {
		return false
	}
	id, ok := unparen(ta.X).(*ast.Ident)
	return ok && ef.info.Uses[id] == v
}

func (ef *errFlow) listsLibType(cc *ast.CaseClause) bool {
	for _, e := range cc.List {
		if t := ef.info.TypeOf(e); t != nil && ef.libErrorType(t) != nil {
			return true
		}
	}
	return false
}

// returnsWhenMatched reports whether st is an if, a tagless switch or a type switch with a check whose
// matching branch can't complete normally, so the error isn't the library type after it.
func returnsWhenMatched(st ast.Stmt, check typeCheck, caseCheck typeCaseCheck) bool {
	switch s := st.(type) {
	case *ast.IfStmt:
		negated, ok := check(s.Cond, s.Init)
		return ok && !negated && terminates(s.Body.List)
	case *ast.SwitchStmt:
		if s.Tag != nil {
			return false
		}
		for _, c := range s.Body.List {
			if cc := c.(*ast.CaseClause); matchesCase(cc, s.Init, check) && terminates(cc.Body) {
				return true
			}
		}
	case *ast.TypeSwitchStmt:
		for _, c := range s.Body.List {
			if cc := c.(*ast.CaseClause); caseCheck(s, cc) && terminates(cc.Body) {
				return true
			}
		}
	}
	return false
}

// matchesCase reports whether one of cc's expressions is a check that isn't negated.
func matchesCase(cc *ast.CaseClause, init ast.Stmt, check typeCheck) bool {
	for _, e := range cc.List {
		if negated, ok := check(e, init); ok && !negated {
			return true
		}
	}
	return false
}

func stmtList(n ast.Node) []ast.Stmt {
	switch s := n.(type) {
	case *ast.BlockStmt:
		return s.List
	case *ast.CaseClause:
		return s.Body
	case *ast.CommClause:
		return s.Body
	}
	return nil
}

// libTypeCheck matches a condition that checks v for a library error type, possibly negated:
// errors.As(v, &target), or the ok of `target, ok := errors.AsType[T](v)` or `target, ok := v.(T)` in
// init. It returns the errors.As or errors.AsType call or the type assertion, or nil.
func (ef *errFlow) libTypeCheck(cond ast.Expr, init ast.Stmt, v types.Object) (found ast.Expr, negated bool) {
	cond = unparen(cond)
	if u, isNot := cond.(*ast.UnaryExpr); isNot && u.Op == token.NOT {
		negated, cond = true, unparen(u.X)
	}
	var call *ast.CallExpr
	switch c := cond.(type) {
	case *ast.CallExpr:
		call = c
	case *ast.Ident:
		as, isAssign := init.(*ast.AssignStmt)
		if !isAssign || len(as.Lhs) != 2 || len(as.Rhs) != 1 {
			return nil, false
		}
		if id, isIdent := as.Lhs[1].(*ast.Ident); !isIdent || ef.info.ObjectOf(id) != ef.info.ObjectOf(c) {
			return nil, false
		}
		if ta, isAssert := unparen(as.Rhs[0]).(*ast.TypeAssertExpr); isAssert && ta.Type != nil {
			id, isIdent := unparen(ta.X).(*ast.Ident)
			if !isIdent || ef.info.Uses[id] != v || ef.libErrorType(ef.info.TypeOf(ta.Type)) == nil {
				return nil, false
			}
			return ta, negated
		}
		call, _ = unparen(as.Rhs[0]).(*ast.CallExpr)
	}
	if call == nil || len(call.Args) == 0 {
		return nil, false
	}
	if id, isIdent := unparen(call.Args[0]).(*ast.Ident); !isIdent || ef.info.Uses[id] != v {
		return nil, false
	}
	var target types.Type
	switch obj := calleeObj(ef.info, call); {
	case isPkgFunc(obj, "errors", "As") && len(call.Args) == 2:
		if ptr, isPtr := ef.info.TypeOf(call.Args[1]).(*types.Pointer); isPtr {
			target = ptr.Elem()
		}
	case isPkgFunc(obj, "errors", "AsType"):
		if ie, isIndex := call.Fun.(*ast.IndexExpr); isIndex {
			target = ef.info.TypeOf(ie.Index)
		}
	}
	if target == nil || ef.libErrorType(target) == nil {
		return nil, false
	}
	return call, negated
}

// terminates reports whether a statement list ends in a terminating statement as the Go spec defines
// it: control can't reach the end of the list.
func terminates(list []ast.Stmt) bool {
	if len(list) == 0 {
		return false
	}
	return isTerminating(list[len(list)-1], "")
}

func isTerminating(st ast.Stmt, label string) bool {
	switch s := st.(type) {
	case *ast.ReturnStmt:
		return true
	case *ast.BranchStmt:
		return s.Tok == token.GOTO
	case *ast.ExprStmt:
		call, ok := unparen(s.X).(*ast.CallExpr)
		if !ok {
			return false
		}
		id, ok := unparen(call.Fun).(*ast.Ident)
		return ok && id.Name == "panic"
	case *ast.BlockStmt:
		return terminates(s.List)
	case *ast.LabeledStmt:
		return isTerminating(s.Stmt, s.Label.Name)
	case *ast.IfStmt:
		if s.Else == nil || !terminates(s.Body.List) {
			return false
		}
		return isTerminating(s.Else, "")
	case *ast.ForStmt:
		return s.Cond == nil && !hasBreak(s.Body, label)
	case *ast.SwitchStmt:
		return clausesTerminate(s.Body, label)
	case *ast.TypeSwitchStmt:
		return clausesTerminate(s.Body, label)
	case *ast.SelectStmt:
		for _, c := range s.Body.List {
			cc := c.(*ast.CommClause)
			if !terminates(cc.Body) || hasBreakIn(cc.Body, label) {
				return false
			}
		}
		return true
	}
	return false
}

func clausesTerminate(body *ast.BlockStmt, label string) bool {
	hasDefault := false
	for _, c := range body.List {
		cc := c.(*ast.CaseClause)
		if cc.List == nil {
			hasDefault = true
		}
		if !terminates(cc.Body) && !endsInFallthrough(cc.Body) || hasBreakIn(cc.Body, label) {
			return false
		}
	}
	return hasDefault
}

func hasBreakIn(list []ast.Stmt, label string) bool {
	for _, st := range list {
		if hasBreak(st, label) {
			return true
		}
	}
	return false
}

// hasBreak reports whether n has a break that leaves the statement it's in: an unlabeled one outside
// any nested loop, switch or select, or one with label.
func hasBreak(n ast.Node, label string) bool {
	found := false
	var walk func(n ast.Node, nested bool)
	walk = func(n ast.Node, nested bool) {
		ast.Inspect(n, func(c ast.Node) bool {
			if found || c == nil {
				return false
			}
			switch x := c.(type) {
			case *ast.FuncLit:
				return false
			case *ast.BranchStmt:
				if x.Tok == token.BREAK && (x.Label == nil && !nested || x.Label != nil && x.Label.Name == label && label != "") {
					found = true
				}
			case *ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt:
				if !nested {
					walk(c, true)
					return false
				}
			}
			return true
		})
	}
	walk(n, false)
	return found
}

func endsInFallthrough(list []ast.Stmt) bool {
	if len(list) == 0 {
		return false
	}
	b, ok := list[len(list)-1].(*ast.BranchStmt)
	return ok && b.Tok == token.FALLTHROUGH
}
