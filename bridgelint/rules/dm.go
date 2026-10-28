package rules

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"

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
	if !ef.libErrorTypes || !isErrorType(t) || isRespErrorType(t) {
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

// ruledOutLibType reports whether use, a use of the error v, is where the function already knows v isn't
// the library error type it checked for: in the branch of the check that didn't match, or after one
// whose matching branch returns.
func (ef *errFlow) ruledOutLibType(fn ast.Node, use ast.Node, v types.Object) bool {
	var prev ast.Node = use
	for p := ef.pi.parents[use]; p != nil && p != fn; prev, p = p, ef.pi.parents[p] {
		switch s := p.(type) {
		case *ast.IfStmt:
			if negated, ok := ef.libTypeCheck(s, v); ok && (prev == s.Body && negated || prev == s.Else && !negated) {
				return true
			}
		default:
			for _, st := range stmtList(p) {
				if st == prev {
					break
				}
				if ifs, ok := st.(*ast.IfStmt); ok {
					if negated, ok := ef.libTypeCheck(ifs, v); ok && !negated && endsInReturn(ifs.Body) {
						return true
					}
				}
			}
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

// libTypeCheck matches an if whose whole condition checks v for a library error type, possibly negated:
// errors.As(v, &target), or the ok of `target, ok := errors.AsType[T](v)` in its init.
func (ef *errFlow) libTypeCheck(ifs *ast.IfStmt, v types.Object) (negated, ok bool) {
	cond := unparen(ifs.Cond)
	if u, isNot := cond.(*ast.UnaryExpr); isNot && u.Op == token.NOT {
		negated, cond = true, unparen(u.X)
	}
	var call *ast.CallExpr
	switch c := cond.(type) {
	case *ast.CallExpr:
		call = c
	case *ast.Ident:
		as, isAssign := ifs.Init.(*ast.AssignStmt)
		if !isAssign || len(as.Lhs) != 2 || len(as.Rhs) != 1 {
			return false, false
		}
		if id, isIdent := as.Lhs[1].(*ast.Ident); !isIdent || ef.info.ObjectOf(id) != ef.info.ObjectOf(c) {
			return false, false
		}
		call, _ = unparen(as.Rhs[0]).(*ast.CallExpr)
	}
	if call == nil || len(call.Args) == 0 {
		return false, false
	}
	if id, isIdent := unparen(call.Args[0]).(*ast.Ident); !isIdent || ef.info.Uses[id] != v {
		return false, false
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
	return negated, target != nil && ef.libErrorType(target) != nil
}

func endsInReturn(b *ast.BlockStmt) bool {
	if len(b.List) == 0 {
		return false
	}
	_, ok := b.List[len(b.List)-1].(*ast.ReturnStmt)
	return ok
}
