package rules

import (
	"fmt"
	"go/ast"
	"go/types"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/types/typeutil"
)

// errSummary is the cross-package summary of what a function's trailing error result can be. It lets
// errflow see through calls into other packages of the same module (message converters, the bridge's own
// network library) instead of guessing from the signature.
type errSummary struct {
	Kind       errKind
	Msg        string
	CalleePkg  string // package name of the raw origin, for messages
	CalleeName string // function name of the raw origin, for messages
	FormatsErr bool
	Network    bool // the function can reach the network
	Opaque     bool // the function makes context-taking calls through interfaces or func values
	Statuses   bool // the function returns bridgev2 statuses itself, so its errors are meant for the bridge
}

func (s errSummary) String() string {
	kind := map[errKind]string{errConstructed: "constructed", errRaw: "raw", errJoin: "join"}[s.Kind]
	return fmt.Sprintf("%s msg=%q callee=%s.%s network=%t opaque=%t statuses=%t", kind, s.Msg, s.CalleePkg, s.CalleeName, s.Network, s.Opaque, s.Statuses)
}

// Each analyzer needs its own fact type: go/analysis doesn't allow two analyzers to register the same one.
type mssErrFact struct{ S errSummary }
type lpErrFact struct{ S errSummary }
type bsErrFact struct{ S errSummary }

func (*mssErrFact) AFact() {}
func (*lpErrFact) AFact()  {}
func (*bsErrFact) AFact()  {}

func (f *mssErrFact) String() string { return f.S.String() }
func (f *lpErrFact) String() string  { return f.S.String() }
func (f *bsErrFact) String() string  { return f.S.String() }

func (f *mssErrFact) summary() *errSummary { return &f.S }
func (f *lpErrFact) summary() *errSummary  { return &f.S }
func (f *bsErrFact) summary() *errSummary  { return &f.S }

type errFact interface {
	analysis.Fact
	summary() *errSummary
}

func newMSSFact() errFact { return new(mssErrFact) }
func newLPFact() errFact  { return new(lpErrFact) }
func newBSFact() errFact  { return new(bsErrFact) }

// withFacts makes ef import summaries for functions in other packages of the module, and exports
// summaries for every function in this package that returns an error or reaches the network.
func (ef *errFlow) withFacts(pass *analysis.Pass, newFact func() errFact) *errFlow {
	ef.factPass = pass
	ef.newFact = newFact
	if pass.Module != nil {
		ef.modulePath = pass.Module.Path
	}
	if pass.TypesInfo == nil || ef.modulePath == "" {
		return ef
	}
	network, opaque := ef.networkFuncs()
	for obj, fd := range ef.pi.decls {
		fact := newFact()
		s := fact.summary()
		s.Network, s.Opaque = network[fd], opaque[fd]
		s.Statuses = ef.returnsStatuses(fd)
		if sig, ok := obj.Type().(*types.Signature); ok {
			if idx := errorResultIndex(sig); idx >= 0 {
				o := ef.funcOrigin(fd, idx, ef.cfg.HelperDepth)
				if o.bad() {
					s.Kind, s.Msg, s.FormatsErr = o.kind, o.msg, o.formatsErr
					s.CalleePkg, s.CalleeName = o.calleePkgName(), o.calleeFuncName()
				}
			}
		}
		if s.Kind != errUnknown || s.Network || s.Opaque || s.Statuses {
			pass.ExportObjectFact(obj, fact)
		}
	}
	return ef
}

// networkFuncs finds the functions in this package that can reach the network: they send an HTTP
// request, dial, call a network library, or call another function that does. It also finds the ones
// that make context-taking calls it can't see through (interfaces, func values), which might.
// Calls made from goroutines they start don't count, since their errors can't be returned.
func (ef *errFlow) networkFuncs() (network, opaque map[*ast.FuncDecl]bool) {
	if ef.network != nil {
		return ef.network, ef.opaque
	}
	ef.network, ef.opaque = map[*ast.FuncDecl]bool{}, map[*ast.FuncDecl]bool{}
	callers := map[*ast.FuncDecl][]*ast.FuncDecl{}
	for _, fd := range ef.pi.decls {
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if _, ok := n.(*ast.GoStmt); ok {
				return false
			}
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			f, ok := typeutil.Callee(ef.info, call).(*types.Func)
			if !ok {
				if ef.passesContext(call) {
					ef.opaque[fd] = true
				}
				return true
			}
			f = f.Origin()
			if callee := ef.pi.decls[f]; callee != nil {
				callers[callee] = append(callers[callee], fd)
				return true
			}
			switch ef.callKind(f) {
			case callNetwork:
				ef.network[fd] = true
			case callOpaque:
				ef.opaque[fd] = true
			}
			return true
		})
	}
	propagate := func(set map[*ast.FuncDecl]bool) {
		var work []*ast.FuncDecl
		for fd := range set {
			work = append(work, fd)
		}
		for len(work) > 0 {
			fd := work[len(work)-1]
			work = work[:len(work)-1]
			for _, caller := range callers[fd] {
				if !set[caller] {
					set[caller] = true
					work = append(work, caller)
				}
			}
		}
	}
	propagate(ef.network)
	propagate(ef.opaque)
	return ef.network, ef.opaque
}

func (ef *errFlow) passesContext(call *ast.CallExpr) bool {
	for _, arg := range call.Args {
		if isNamed(ef.info.TypeOf(arg), "context", "Context") {
			return true
		}
	}
	return false
}

type callKind int

const (
	callLocal callKind = iota
	callNetwork
	callOpaque
)

func (ef *errFlow) callKind(f *types.Func) callKind {
	if f.Pkg() == nil {
		return callLocal
	}
	sig, ok := f.Type().(*types.Signature)
	if !ok {
		return callLocal
	}
	path := f.Pkg().Path()
	switch {
	case isHTTPRoundTrip(f), path == "net" && strings.HasPrefix(f.Name(), "Dial"), ef.isConnIO(f):
		return callNetwork
	case ef.inModule(path):
		fact := ef.newFact()
		if !ef.factPass.ImportObjectFact(f, fact) {
			if isInterfaceMethod(f) && takesContext(sig) {
				return callOpaque
			}
			return callLocal
		}
		switch s := fact.summary(); {
		case s.Network:
			return callNetwork
		case s.Opaque:
			return callOpaque
		}
		return callLocal
	case path == "net/http":
		return callLocal
	case isNetworkPackage(ef.cfg, ef.pi.pass.Pkg, path) && takesContext(sig):
		return callNetwork
	case isInterfaceMethod(f) && takesContext(sig) && path == ef.pi.pass.Pkg.Path():
		return callOpaque
	}
	return callLocal
}

// isConnIO matches reads and writes on a connection: net.Conn and other Conn types from net, crypto/tls
// or a network library (gorilla/websocket and the like).
func (ef *errFlow) isConnIO(f *types.Func) bool {
	sig := f.Type().(*types.Signature)
	if sig.Recv() == nil || !(strings.HasPrefix(f.Name(), "Read") || strings.HasPrefix(f.Name(), "Write") || strings.HasPrefix(f.Name(), "Next")) {
		return false
	}
	t := sig.Recv().Type()
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := t.(*types.Named)
	if !ok || named.Obj().Name() != "Conn" || named.Obj().Pkg() == nil {
		return false
	}
	path := named.Obj().Pkg().Path()
	return path == "net" || path == "crypto/tls" || !ef.inModule(path) && isNetworkPackage(ef.cfg, ef.pi.pass.Pkg, path)
}

func isInterfaceMethod(f *types.Func) bool {
	sig, ok := f.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return false
	}
	_, ok = sig.Recv().Type().Underlying().(*types.Interface)
	return ok
}

// returnsStatuses reports whether fd itself returns bridgev2 message statuses or RespErrors (directly,
// or wrapped with fmt.Errorf), like a message converter does.
func (ef *errFlow) returnsStatuses(fd *ast.FuncDecl) bool {
	sig, ok := ef.info.Defs[fd.Name].Type().(*types.Signature)
	if !ok {
		return false
	}
	idx := errorResultIndex(sig)
	if idx < 0 {
		return false
	}
	found := false
	inspectFunc(fd.Body, func(n ast.Node) bool {
		ret, ok := n.(*ast.ReturnStmt)
		if !ok || found || len(ret.Results) != sig.Results().Len() {
			return !found
		}
		e := unparen(ret.Results[idx])
		if call, ok := e.(*ast.CallExpr); ok && isPkgFunc(calleeObj(ef.info, call), "fmt", "Errorf") {
			for _, arg := range call.Args[1:] {
				if ef.isStatusExpr(arg) {
					found = true
				}
			}
			return !found
		}
		found = ef.isStatusExpr(e)
		return !found
	})
	return found
}

func (ef *errFlow) isStatusExpr(e ast.Expr) bool {
	e = unparen(e)
	if t := ef.info.TypeOf(e); t != nil && (isNamed(t, pathBridgev2, "MessageStatus") || isRespErrorType(t)) {
		return true
	}
	var id *ast.Ident
	switch x := e.(type) {
	case *ast.SelectorExpr:
		id = x.Sel
	case *ast.Ident:
		id = x
	default:
		return false
	}
	v, ok := ef.info.Uses[id].(*types.Var)
	return ok && v.Pkg() != nil && v.Pkg().Path() == pathBridgev2
}

// inModule reports whether path is another package of the module being linted. Those packages are
// analysed from source, so their summaries are used instead of the network-package heuristic.
func (ef *errFlow) inModule(path string) bool {
	if ef.factPass == nil || ef.modulePath == "" || path == ef.pi.pass.Pkg.Path() {
		return false
	}
	return path == ef.modulePath || strings.HasPrefix(path, ef.modulePath+"/")
}

// importedOrigin returns the origin of an error returned by f, a function in another package of the
// module. Functions without a summary only return nil, good or unclassifiable errors.
func (ef *errFlow) importedOrigin(f *types.Func, call *ast.CallExpr) errOrigin {
	fact := ef.newFact()
	if !ef.factPass.ImportObjectFact(f, fact) {
		return errOrigin{}
	}
	s := fact.summary()
	if !s.Statuses {
		// A library function: any network error escaping it is a library error as far as the bridge is
		// concerned, even if the library wrapped it or built it itself. Functions that call through
		// interfaces can't be followed, so those fall back to the context heuristic used for other
		// libraries. Errors the library builds without touching the network are internal invariants.
		if s.Network || s.Opaque && takesContext(f.Type().(*types.Signature)) || s.Kind == errRaw || s.Kind == errConstructed && s.CalleeName != "" {
			return errOrigin{kind: errRaw, node: call, callee: f}
		}
		return errOrigin{}
	}
	return errOrigin{
		kind:       s.Kind,
		node:       call,
		msg:        s.Msg,
		calleePkg:  s.CalleePkg,
		calleeFn:   s.CalleeName,
		formatsErr: s.FormatsErr,
		via:        f.Pkg().Name() + "." + f.Name(),
	}
}
