package rules

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"golang.org/x/tools/go/types/typeutil"
)

type errKind int

const (
	errUnknown     errKind = iota // can't tell; never reported
	errGood                       // typed error, status, RespError, mapper output or nil
	errConstructed                // errors.New or fmt.Errorf without wrapping anything typed
	errRaw                        // returned unchanged from a network or library call
	errJoin                       // errors.Join
)

type errOrigin struct {
	kind   errKind
	node   ast.Node
	msg    string
	callee types.Object
	helper *ast.FuncDecl
	// formatsErr is set when a constructed error formats another error or a status code into its text.
	formatsErr bool
}

func (o errOrigin) bad() bool {
	return o.kind == errConstructed || o.kind == errRaw || o.kind == errJoin
}

type errFlow struct {
	pi       *pkgInfo
	info     *types.Info
	cfg      *Config
	mappers  map[string]bool
	visiting map[*ast.FuncDecl]bool
}

func newErrFlow(pi *pkgInfo, cfg *Config, mappers ...[]string) *errFlow {
	ef := &errFlow{pi: pi, info: pi.pass.TypesInfo, cfg: cfg, mappers: map[string]bool{}, visiting: map[*ast.FuncDecl]bool{}}
	for _, list := range mappers {
		for _, m := range list {
			ef.mappers[m] = true
		}
	}
	return ef
}

// errorResultIndex returns the index of the trailing error result, or -1.
func errorResultIndex(sig *types.Signature) int {
	if sig == nil || sig.Results().Len() == 0 {
		return -1
	}
	last := sig.Results().Len() - 1
	if isErrorInterface(sig.Results().At(last).Type()) {
		return last
	}
	return -1
}

// returnedErrors calls fn for the error expression of every return statement in body.
func (ef *errFlow) returnedErrors(fn ast.Node, idx int, cb func(ret *ast.ReturnStmt, origin errOrigin)) {
	inspectFunc(funcBody(fn), func(n ast.Node) bool {
		ret, ok := n.(*ast.ReturnStmt)
		if !ok {
			return true
		}
		origin := ef.originOfReturn(fn, ret, idx, ef.cfg.HelperDepth)
		cb(ret, origin)
		return true
	})
}

func (ef *errFlow) originOfReturn(fn ast.Node, ret *ast.ReturnStmt, idx, depth int) errOrigin {
	sig := funcType(ef.info, fn)
	if sig == nil {
		return errOrigin{}
	}
	switch {
	case len(ret.Results) == sig.Results().Len() && idx < len(ret.Results):
		return ef.classify(fn, ret.Results[idx], ret.Pos(), depth)
	case len(ret.Results) == 1:
		if call, ok := unparen(ret.Results[0]).(*ast.CallExpr); ok {
			return ef.classifyCall(fn, call, idx, depth)
		}
	}
	return errOrigin{}
}

func (ef *errFlow) classify(fn ast.Node, e ast.Expr, at token.Pos, depth int) errOrigin {
	e = unparen(e)
	if t := ef.info.TypeOf(e); t != nil && !isErrorInterface(t) {
		if _, isTuple := t.(*types.Tuple); !isTuple {
			return errOrigin{kind: errGood}
		}
	}
	switch x := e.(type) {
	case *ast.Ident:
		if x.Name == "nil" {
			return errOrigin{kind: errGood}
		}
		v, ok := ef.info.Uses[x].(*types.Var)
		if !ok {
			return errOrigin{}
		}
		if v.Parent() == v.Pkg().Scope() {
			return ef.classifyPkgVar(v, x, depth)
		}
		return ef.classifyLocal(fn, v, at, depth)
	case *ast.SelectorExpr:
		if v, ok := ef.info.Uses[x.Sel].(*types.Var); ok && v.Pkg() != nil && v.Parent() == v.Pkg().Scope() {
			return ef.classifyPkgVar(v, x, depth)
		}
		return errOrigin{}
	case *ast.CallExpr:
		return ef.classifyCall(fn, x, -1, depth)
	}
	return errOrigin{}
}

func (ef *errFlow) classifyPkgVar(v *types.Var, node ast.Node, depth int) errOrigin {
	if v.Pkg() == ef.pi.pass.Pkg {
		init := ef.pkgVarInit(v)
		if init == nil {
			return errOrigin{}
		}
		o := ef.classify(nil, init, token.NoPos, depth)
		if o.kind == errConstructed {
			o.node = node
			o.msg = fmt.Sprintf("%s (%q)", v.Name(), o.msg)
		}
		return o
	}
	if isNetworkPackage(ef.cfg, ef.pi.pass.Pkg, v.Pkg().Path()) {
		return errOrigin{kind: errRaw, node: node, callee: v}
	}
	return errOrigin{kind: errGood}
}

func (ef *errFlow) pkgVarInit(v *types.Var) ast.Expr {
	for _, f := range ef.pi.pass.Files {
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, spec := range gd.Specs {
				vs := spec.(*ast.ValueSpec)
				for i, name := range vs.Names {
					if ef.info.Defs[name] == v && i < len(vs.Values) {
						return vs.Values[i]
					}
				}
			}
		}
	}
	return nil
}

// classifyLocal finds the last assignment to v before at.
func (ef *errFlow) classifyLocal(fn ast.Node, v *types.Var, at token.Pos, depth int) errOrigin {
	body := funcBody(fn)
	if body == nil {
		return errOrigin{}
	}
	var bestPos token.Pos
	var bestRHS []ast.Expr
	bestIdx, bestLHSLen := -1, 0
	consider := func(lhs []ast.Expr, rhs []ast.Expr, pos token.Pos) {
		for i, l := range lhs {
			id, ok := unparen(l).(*ast.Ident)
			if !ok {
				continue
			}
			if ef.info.Defs[id] != v && ef.info.Uses[id] != v {
				continue
			}
			if pos < at && pos > bestPos {
				bestPos, bestRHS, bestIdx, bestLHSLen = pos, rhs, i, len(lhs)
			}
		}
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.AssignStmt:
			consider(s.Lhs, s.Rhs, s.Pos())
		case *ast.ValueSpec:
			lhs := make([]ast.Expr, len(s.Names))
			for i, name := range s.Names {
				lhs[i] = name
			}
			consider(lhs, s.Values, s.Pos())
		}
		return true
	})
	switch {
	case bestIdx < 0:
		return errOrigin{}
	case len(bestRHS) == 0:
		return errOrigin{kind: errGood}
	case len(bestRHS) == bestLHSLen:
		return ef.classify(fn, bestRHS[bestIdx], bestPos, depth)
	case len(bestRHS) == 1:
		if call, ok := unparen(bestRHS[0]).(*ast.CallExpr); ok {
			return ef.classifyCall(fn, call, bestIdx, depth)
		}
	}
	return errOrigin{}
}

func (ef *errFlow) classifyCall(fn ast.Node, call *ast.CallExpr, idx, depth int) errOrigin {
	if tv, ok := ef.info.Types[call.Fun]; ok && tv.IsType() {
		return errOrigin{kind: errGood}
	}
	callee := typeutil.Callee(ef.info, call)
	f, ok := callee.(*types.Func)
	if !ok {
		return errOrigin{}
	}
	f = f.Origin()
	sig := f.Type().(*types.Signature)
	if idx < 0 {
		idx = sig.Results().Len() - 1
	}
	if idx < 0 || idx >= sig.Results().Len() {
		return errOrigin{}
	}
	if !isErrorInterface(sig.Results().At(idx).Type()) {
		if isErrorType(sig.Results().At(idx).Type()) {
			return errOrigin{kind: errGood}
		}
		return errOrigin{}
	}
	switch {
	case isPkgFunc(f, "errors", "New"):
		msg, _ := stringArg(ef.info, call, 0)
		return errOrigin{kind: errConstructed, node: call, msg: msg}
	case isPkgFunc(f, "errors", "Join"):
		return errOrigin{kind: errJoin, node: call}
	case isPkgFunc(f, "fmt", "Errorf"):
		return ef.classifyErrorf(fn, call, depth)
	case isPkgFunc(f, "errors", "Unwrap"):
		return errOrigin{}
	}
	if ef.mappers[f.Name()] {
		return errOrigin{kind: errGood}
	}
	if fd := ef.pi.decls[f]; fd != nil {
		if depth <= 0 || ef.visiting[fd] {
			return errOrigin{}
		}
		ef.visiting[fd] = true
		defer delete(ef.visiting, fd)
		var worst errOrigin
		inspectFunc(fd.Body, func(n ast.Node) bool {
			ret, ok := n.(*ast.ReturnStmt)
			if !ok {
				return true
			}
			o := ef.originOfReturn(fd, ret, idx, depth-1)
			if o.bad() && (!worst.bad() || o.kind == errRaw && worst.kind != errRaw) {
				worst = o
				if worst.helper == nil {
					worst.helper = fd
				}
			}
			return true
		})
		return worst
	}
	// Network calls take a context; parsers and converters that don't are treated as internal.
	if f.Pkg() != nil && isNetworkPackage(ef.cfg, ef.pi.pass.Pkg, f.Pkg().Path()) && takesContext(sig) {
		return errOrigin{kind: errRaw, node: call, callee: f}
	}
	return errOrigin{}
}

func (ef *errFlow) classifyErrorf(fn ast.Node, call *ast.CallExpr, depth int) errOrigin {
	format, ok := stringArg(ef.info, call, 0)
	o := errOrigin{kind: errConstructed, node: call, msg: format}
	for _, arg := range call.Args[1:] {
		if t := ef.info.TypeOf(arg); isErrorType(t) || looksLikeStatusCode(arg) {
			o.formatsErr = true
		}
	}
	if !ok {
		return o
	}
	// Arguments are evaluated before the enclosing statement assigns anything, so look up locals from the
	// statement's position. Otherwise `err = fmt.Errorf("...: %w", err)` resolves err to itself forever.
	at := call.Pos()
	for p := ef.pi.parents[call]; p != nil; p = ef.pi.parents[p] {
		if _, ok := p.(ast.Stmt); ok {
			at = p.Pos()
			break
		}
	}
	for _, argIdx := range wrapVerbArgs(format) {
		if argIdx+1 >= len(call.Args) {
			continue
		}
		inner := ef.classify(fn, call.Args[argIdx+1], at, depth)
		if !inner.bad() {
			return errOrigin{kind: inner.kind, formatsErr: o.formatsErr}
		}
		if inner.kind == errRaw {
			o.callee = inner.callee
		}
	}
	return o
}

func looksLikeStatusCode(e ast.Expr) bool {
	var name string
	switch x := unparen(e).(type) {
	case *ast.SelectorExpr:
		name = x.Sel.Name
	case *ast.Ident:
		name = x.Name
	default:
		return false
	}
	lower := strings.ToLower(name)
	return strings.Contains(lower, "status") || lower == "code" || strings.HasSuffix(lower, "code")
}

// wrapVerbArgs returns the operand indexes consumed by %w verbs.
func wrapVerbArgs(format string) []int {
	var out []int
	arg := 0
	for i := 0; i < len(format); i++ {
		if format[i] != '%' {
			continue
		}
		i++
		for i < len(format) && strings.IndexByte("+-# 0123456789.*[]", format[i]) >= 0 {
			if format[i] == '*' {
				arg++
			}
			i++
		}
		if i >= len(format) {
			break
		}
		if format[i] == '%' {
			continue
		}
		if format[i] == 'w' {
			out = append(out, arg)
		}
		arg++
	}
	return out
}

func stringArg(info *types.Info, call *ast.CallExpr, i int) (string, bool) {
	if i >= len(call.Args) {
		return "", false
	}
	return constString(info, call.Args[i])
}

func describeOrigin(fset *token.FileSet, o errOrigin) string {
	var s string
	switch o.kind {
	case errConstructed:
		if o.msg != "" {
			s = fmt.Sprintf("plain error %q", o.msg)
		} else {
			s = "plain error"
		}
		if o.callee != nil {
			s += fmt.Sprintf(" wrapping a raw %s error", o.callee.Pkg().Name())
		}
	case errRaw:
		if o.callee != nil {
			s = fmt.Sprintf("raw error from %s.%s", o.callee.Pkg().Name(), o.callee.Name())
		} else {
			s = "raw library error"
		}
	case errJoin:
		s = "errors.Join result"
	}
	if o.helper != nil {
		s += fmt.Sprintf(" (via %s at %s)", o.helper.Name.Name, shortPos(fset, o.node))
	}
	return s
}

func shortPos(fset *token.FileSet, n ast.Node) string {
	if n == nil {
		return "?"
	}
	p := fset.Position(n.Pos())
	name := p.Filename
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		name = name[i+1:]
	}
	return fmt.Sprintf("%s:%d", name, p.Line)
}

func takesContext(sig *types.Signature) bool {
	for i := 0; i < sig.Params().Len(); i++ {
		if isNamed(sig.Params().At(i).Type(), "context", "Context") {
			return true
		}
	}
	return false
}
