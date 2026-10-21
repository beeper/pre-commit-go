package rules

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/types/typeutil"
)

type errKind int

const (
	errUnknown     errKind = iota // can't tell; never reported
	errGood                       // typed error, status, RespError, mapper output or nil
	errConstructed                // errors.New or fmt.Errorf without wrapping anything typed
	errRaw                        // returned unchanged from a network or library call
	errJoin                       // errors.Join
	errInternal                   // from a call that can't reach the network; never reported
)

type errOrigin struct {
	kind   errKind
	node   ast.Node
	msg    string
	callee types.Object
	helper *ast.FuncDecl
	// formatsErr is set when a constructed error formats another error or a status code into its text.
	formatsErr bool
	// calleePkg and calleeFn name the raw origin when it's only known from another package's summary.
	calleePkg, calleeFn string
	// via names the function in another package of the module that the error came through.
	via string
	// partial is set when some of the returns the origin was picked from couldn't be classified.
	partial bool
}

func (o errOrigin) hasCallee() bool {
	return o.callee != nil || o.calleeFn != ""
}

func (o errOrigin) calleePkgName() string {
	if o.callee != nil && o.callee.Pkg() != nil {
		return o.callee.Pkg().Name()
	}
	return o.calleePkg
}

func (o errOrigin) calleeFuncName() string {
	if o.callee != nil {
		return o.callee.Name()
	}
	return o.calleeFn
}

func (o errOrigin) bad() bool {
	return o.kind == errConstructed || o.kind == errRaw || o.kind == errJoin
}

// severity ranks bad origins for picking the one a function reports: a raw network error, then a plain
// error wrapping one, then one that formats an error or status code into its text, then the rest.
func (o errOrigin) severity() int {
	switch {
	case o.kind == errRaw:
		return 4
	case o.kind == errConstructed && o.hasCallee():
		return 3
	case o.bad() && o.formatsErr:
		return 2
	case o.bad():
		return 1
	}
	return 0
}

type errFlow struct {
	pi       *pkgInfo
	info     *types.Info
	cfg      *Config
	mappers  []string
	visiting map[*ast.FuncDecl]bool

	factPass   *analysis.Pass
	newFact    func() errFact
	modulePath string
	net        *netReach
	deferCache map[ast.Node]bool
}

func newErrFlow(pass *analysis.Pass, pi *pkgInfo, cfg *Config, mappers ...[]string) *errFlow {
	ef := &errFlow{pi: pi, info: pi.pass.TypesInfo, cfg: cfg, visiting: map[*ast.FuncDecl]bool{}, deferCache: map[ast.Node]bool{}}
	ef.net = netOf(pass)
	for _, list := range mappers {
		ef.mappers = append(ef.mappers, list...)
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
	if ef.rewrittenByDefer(fn, sig, idx) {
		return errOrigin{kind: errGood}
	}
	switch {
	case len(ret.Results) == sig.Results().Len() && idx < len(ret.Results):
		if ef.guardedByStatusIs(fn, ret, ret.Results[idx]) {
			return errOrigin{kind: errGood}
		}
		o := ef.classify(fn, ret.Results[idx], ret.Pos(), depth)
		if v, ok := o.callee.(*types.Var); ok && o.bad() && ef.deferMapsSentinel(fn, sig, idx, v) {
			return errOrigin{kind: errGood}
		}
		return o
	case len(ret.Results) == 1:
		if call, ok := unparen(ret.Results[0]).(*ast.CallExpr); ok {
			return ef.classifyCall(fn, call, idx, depth)
		}
	}
	return errOrigin{}
}

// rewrittenByDefer reports whether fn has a deferred closure that maps every error it returns: it
// reassigns its named error result from a call that takes the error, at most under an `err != nil` check.
// The value at each return statement isn't what the caller gets, so it isn't classified. Deferred code
// that only maps some errors doesn't count.
func (ef *errFlow) rewrittenByDefer(fn ast.Node, sig *types.Signature, idx int) bool {
	if idx < 0 || idx >= sig.Results().Len() || sig.Results().At(idx).Name() == "" {
		return false
	}
	if v, ok := ef.deferCache[fn]; ok {
		return v
	}
	result := sig.Results().At(idx)
	found := false
	defer func() { ef.deferCache[fn] = found }()
	refersToResult := func(e ast.Node) bool {
		refers := false
		ast.Inspect(e, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && ef.info.Uses[id] == result {
				refers = true
			}
			return !refers
		})
		return refers
	}
	inspectFunc(funcBody(fn), func(n ast.Node) bool {
		def, ok := n.(*ast.DeferStmt)
		if !ok || found {
			return !found
		}
		lit, ok := def.Call.Fun.(*ast.FuncLit)
		if !ok {
			return true
		}
		ast.Inspect(lit.Body, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok || found || len(as.Lhs) != len(as.Rhs) {
				return !found
			}
			for i, l := range as.Lhs {
				id, ok := unparen(l).(*ast.Ident)
				if !ok || ef.info.Uses[id] != result {
					continue
				}
				if _, isCall := unparen(as.Rhs[i]).(*ast.CallExpr); !isCall || !refersToResult(as.Rhs[i]) {
					continue
				}
				if ef.onlyUnderNilCheck(as, lit, result) {
					found = true
				}
			}
			return !found
		})
		return !found
	})
	return found
}

// guardedByStatusIs reports whether ret returns a local error inside `if errors.Is(err, S)`, where S is
// a message status or RespError, or inside `if errors.As(err, &target)` with a target of one of those
// types: the returned error contains the status, so the caller gets it.
func (ef *errFlow) guardedByStatusIs(fn ast.Node, ret *ast.ReturnStmt, e ast.Expr) bool {
	id, ok := unparen(e).(*ast.Ident)
	if !ok {
		return false
	}
	v := ef.info.Uses[id]
	if v == nil {
		return false
	}
	var prev ast.Node = ret
	for p := ef.pi.parents[ret]; p != nil && p != fn; prev, p = p, ef.pi.parents[p] {
		ifs, ok := p.(*ast.IfStmt)
		if !ok || prev != ifs.Body {
			continue
		}
		if ef.condIsStatus(ifs.Cond, v, ef.isStatusTarget) {
			return true
		}
	}
	return false
}

// isStatusTarget matches the second argument of errors.Is (a status value) or errors.As (a pointer to
// a status variable).
func (ef *errFlow) isStatusTarget(arg ast.Expr) bool {
	if u, ok := unparen(arg).(*ast.UnaryExpr); ok && u.Op == token.AND {
		t := ef.info.TypeOf(u.X)
		if ptr, ok := t.(*types.Pointer); ok {
			t = ptr.Elem()
		}
		return t != nil && (isNamed(t, pathBridgev2, "MessageStatus") || isRespErrorType(t))
	}
	return ef.isStatusExpr(arg)
}

// condIsStatus reports whether cond is (or is a && conjunct of) errors.Is(v, S) with match(S).
func (ef *errFlow) condIsStatus(cond ast.Expr, v types.Object, match func(ast.Expr) bool) bool {
	cond = unparen(cond)
	if be, ok := cond.(*ast.BinaryExpr); ok && be.Op == token.LAND {
		return ef.condIsStatus(be.X, v, match) || ef.condIsStatus(be.Y, v, match)
	}
	call, ok := cond.(*ast.CallExpr)
	if !ok || len(call.Args) != 2 || !isPkgFunc(calleeObj(ef.info, call), "errors", "Is", "As") {
		return false
	}
	id, ok := unparen(call.Args[0]).(*ast.Ident)
	return ok && ef.info.Uses[id] == v && match(call.Args[1])
}

// deferMapsSentinel reports whether a deferred closure in fn replaces the named error result with a
// status when it matches the sentinel v: `if errors.Is(err, v) { err = <status> }`.
func (ef *errFlow) deferMapsSentinel(fn ast.Node, sig *types.Signature, idx int, v *types.Var) bool {
	if idx < 0 || idx >= sig.Results().Len() || sig.Results().At(idx).Name() == "" {
		return false
	}
	result := sig.Results().At(idx)
	isSentinel := func(e ast.Expr) bool {
		var id *ast.Ident
		switch x := unparen(e).(type) {
		case *ast.Ident:
			id = x
		case *ast.SelectorExpr:
			id = x.Sel
		default:
			return false
		}
		return ef.info.Uses[id] == v
	}
	found := false
	inspectFunc(funcBody(fn), func(n ast.Node) bool {
		def, ok := n.(*ast.DeferStmt)
		if !ok || found {
			return !found
		}
		lit, ok := def.Call.Fun.(*ast.FuncLit)
		if !ok {
			return true
		}
		ast.Inspect(lit.Body, func(n ast.Node) bool {
			ifs, ok := n.(*ast.IfStmt)
			if !ok || found || !ef.condIsStatus(ifs.Cond, result, isSentinel) {
				return !found
			}
			for _, st := range ifs.Body.List {
				as, ok := st.(*ast.AssignStmt)
				if !ok || len(as.Lhs) != len(as.Rhs) {
					continue
				}
				for i, l := range as.Lhs {
					if id, ok := unparen(l).(*ast.Ident); ok && ef.info.Uses[id] == result && ef.isStatusExpr(as.Rhs[i]) {
						found = true
					}
				}
			}
			return !found
		})
		return !found
	})
	return found
}

// onlyUnderNilCheck reports whether every if statement between n and lit checks result != nil.
func (ef *errFlow) onlyUnderNilCheck(n ast.Node, lit *ast.FuncLit, result *types.Var) bool {
	for p := ef.pi.parents[n]; p != nil && p != lit; p = ef.pi.parents[p] {
		ifs, ok := p.(*ast.IfStmt)
		if !ok {
			continue
		}
		be, ok := ifs.Cond.(*ast.BinaryExpr)
		if !ok || be.Op != token.NEQ {
			return false
		}
		x, ok := unparen(be.X).(*ast.Ident)
		y, ok2 := unparen(be.Y).(*ast.Ident)
		if !ok || !ok2 || ef.info.Uses[x] != result || y.Name != "nil" {
			return false
		}
	}
	return true
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
	if ef.net.pkgReaches(v.Pkg()) {
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
	if matchesQualified(f, ef.mappers) {
		return errOrigin{kind: errGood}
	}
	if fd := ef.pi.decls[f]; fd != nil {
		return ef.funcOrigin(fd, idx, depth)
	}
	if f.Pkg() == nil {
		return errOrigin{}
	}
	if ef.inModule(f.Pkg().Path()) {
		if idx != sig.Results().Len()-1 {
			return errOrigin{}
		}
		return ef.importedOrigin(f, call)
	}
	// Errors from library functions that can reach the network are network errors; the rest (parsers,
	// converters, local stores) are internal.
	if ef.net.mightReach(f, false) {
		return errOrigin{kind: errRaw, node: call, callee: f}
	}
	return errOrigin{kind: errInternal}
}

// funcOrigin returns the worst error that fd, a function in this package, can return as result idx.
func (ef *errFlow) funcOrigin(fd *ast.FuncDecl, idx, depth int) errOrigin {
	if depth <= 0 || ef.visiting[fd] {
		return errOrigin{}
	}
	ef.visiting[fd] = true
	defer delete(ef.visiting, fd)
	var worst errOrigin
	partial := false
	inspectFunc(fd.Body, func(n ast.Node) bool {
		ret, ok := n.(*ast.ReturnStmt)
		if !ok {
			return true
		}
		o := ef.originOfReturn(fd, ret, idx, depth-1)
		if o.kind == errUnknown || o.partial {
			partial = true
		}
		if o.severity() > worst.severity() {
			worst = o
			if worst.helper == nil && worst.via == "" {
				worst.helper = fd
			}
		}
		return true
	})
	if worst.kind == errUnknown && !partial {
		worst.kind = errInternal
	}
	worst.partial = partial
	return worst
}

// isHTTPRoundTrip matches calls that send an HTTP request: net/http's helpers, and Do/RoundTrip methods
// taking a *Request on any client (fhttp and other net/http forks). The context comes from the request,
// so they don't take one themselves.
func isHTTPRoundTrip(f *types.Func) bool {
	if f.Pkg() == nil {
		return false
	}
	sig, ok := f.Type().(*types.Signature)
	if !ok {
		return false
	}
	if sig.Recv() == nil {
		return f.Pkg().Path() == "net/http" && (f.Name() == "Get" || f.Name() == "Head" || f.Name() == "Post" || f.Name() == "PostForm")
	}
	if f.Name() != "Do" && f.Name() != "RoundTrip" {
		return false
	}
	for i := 0; i < sig.Params().Len(); i++ {
		if ptr, ok := sig.Params().At(i).Type().(*types.Pointer); ok {
			if named, ok := ptr.Elem().(*types.Named); ok && named.Obj().Name() == "Request" {
				return true
			}
		}
	}
	return false
}

func (ef *errFlow) classifyErrorf(fn ast.Node, call *ast.CallExpr, depth int) errOrigin {
	format, ok := stringArg(ef.info, call, 0)
	o := errOrigin{kind: errConstructed, node: call, msg: format}
	for _, arg := range call.Args[1:] {
		// Package-level sentinels have fixed text, so formatting one doesn't leak anything.
		if t := ef.info.TypeOf(arg); isErrorType(t) && !ef.isPkgVar(arg) || isNetworkStatusField(ef.net, ef.info, arg) {
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
			return errOrigin{kind: inner.kind, formatsErr: o.formatsErr, partial: inner.partial}
		}
		o.partial = o.partial || inner.partial
		if inner.kind == errRaw {
			o.callee, o.calleePkg, o.calleeFn, o.via = inner.callee, inner.calleePkg, inner.calleeFn, inner.via
		}
	}
	return o
}

func (ef *errFlow) isPkgVar(e ast.Expr) bool {
	var id *ast.Ident
	switch x := unparen(e).(type) {
	case *ast.Ident:
		id = x
	case *ast.SelectorExpr:
		id = x.Sel
	default:
		return false
	}
	v, ok := ef.info.Uses[id].(*types.Var)
	return ok && v.Pkg() != nil && v.Parent() == v.Pkg().Scope()
}

func netOf(pass *analysis.Pass) *netReach {
	r, _ := pass.ResultOf[NetAnalyzer].(*netReach)
	return r
}

// isNetworkStatusField reports whether e reads a status or code field of an HTTP response or of a type
// from a network library. Those are protocol-level numbers: formatting one into an error message puts it
// in front of users, and copying one into a RespError sends it as the HTTP status.
func isNetworkStatusField(net *netReach, info *types.Info, e ast.Expr) bool {
	sel, ok := unparen(e).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	switch sel.Sel.Name {
	case "Status", "StatusCode", "Code":
	default:
		return false
	}
	selection, ok := info.Selections[sel]
	if !ok || selection.Kind() != types.FieldVal {
		return false
	}
	if isHTTPStruct(selection.Recv(), "Response") {
		return true
	}
	t := selection.Recv()
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := types.Unalias(t).(*types.Named)
	return ok && named.Obj().Pkg() != nil && net.pkgReaches(named.Obj().Pkg())
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
	flags:
		for i < len(format) {
			switch c := format[i]; {
			case strings.IndexByte("+-# 0123456789.", c) >= 0:
				i++
			case c == '*':
				arg++
				i++
			case c == '[':
				n, end, ok := explicitArgIndex(format, i)
				if !ok {
					break flags
				}
				arg, i = n, end
			default:
				break flags
			}
		}
		if i >= len(format) || format[i] == '%' {
			continue
		}
		if format[i] == 'w' {
			out = append(out, arg)
		}
		arg++
	}
	return out
}

// explicitArgIndex parses an argument index like "[2]" at i, returning the zero-based operand it selects
// and the offset after the "]".
func explicitArgIndex(format string, i int) (arg, end int, ok bool) {
	j := i + 1
	n := 0
	for j < len(format) && format[j] >= '0' && format[j] <= '9' {
		n = n*10 + int(format[j]-'0')
		j++
	}
	if n < 1 || j >= len(format) || format[j] != ']' {
		return 0, i, false
	}
	return n - 1, j + 1, true
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
		if o.hasCallee() {
			s += fmt.Sprintf(" wrapping a raw %s error", o.calleePkgName())
		}
	case errRaw:
		if o.hasCallee() {
			s = fmt.Sprintf("raw error from %s.%s", o.calleePkgName(), o.calleeFuncName())
		} else {
			s = "raw library error"
		}
	case errJoin:
		s = "errors.Join result"
	}
	if o.helper != nil {
		s += fmt.Sprintf(" (via %s at %s)", o.helper.Name.Name, shortPos(fset, o.node))
	} else if o.via != "" {
		s += fmt.Sprintf(" (via %s at %s)", o.via, shortPos(fset, o.node))
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
