package rules

import (
	"fmt"
	"go/ast"
	"go/types"
	"strings"

	"golang.org/x/tools/go/analysis"
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
	Statuses   bool // the function returns bridgev2 statuses itself, so its errors are meant for the bridge
}

func (s errSummary) String() string {
	kind := map[errKind]string{errConstructed: "constructed", errRaw: "raw", errJoin: "join"}[s.Kind]
	return fmt.Sprintf("%s msg=%q callee=%s.%s statuses=%t", kind, s.Msg, s.CalleePkg, s.CalleeName, s.Statuses)
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
	for obj, fd := range ef.pi.decls {
		fact := newFact()
		s := fact.summary()
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
		if s.Kind != errUnknown || s.Statuses {
			pass.ExportObjectFact(obj, fact)
		}
	}
	return ef
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
// module.
func (ef *errFlow) importedOrigin(f *types.Func, call *ast.CallExpr) errOrigin {
	fact := ef.newFact()
	if !ef.factPass.ImportObjectFact(f, fact) {
		if ef.net.mightReach(f, true) {
			return errOrigin{kind: errRaw, node: call, callee: f}
		}
		return errOrigin{}
	}
	s := fact.summary()
	if !s.Statuses {
		// A library function: any network error escaping it is a library error as far as the bridge is
		// concerned, even if the library wrapped it or built it itself. Errors the library builds without
		// touching the network are internal invariants.
		if ef.net.mightReach(f, true) || s.Kind == errRaw || s.Kind == errConstructed && s.CalleeName != "" {
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
