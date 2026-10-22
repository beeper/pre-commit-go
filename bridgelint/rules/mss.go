package rules

import (
	"fmt"
	"go/ast"
	"go/types"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/tools/go/analysis"
)

var MSSAnalyzer = &analysis.Analyzer{
	Name: "mss",
	Doc:  "message status rules (MSS001-MSS006): Matrix handlers must return truthful, human message statuses",
	Run:  runMSS,

	Requires:  []*analysis.Analyzer{NetAnalyzer},
	FactTypes: []analysis.Fact{new(mssErrFact)},
}

// classifierNameRegex matches names with Code, Kind, Class, Reason or Status as a camelCase word, so
// codeOf and slackErrorCode match but decodeError doesn't.
var classifierNameRegex = regexp.MustCompile(`^(code|kind|class|reason|status)|Code|Kind|Class|Reason|Status`)

var permanentReasons = map[string]bool{
	"MessageStatusUnsupported":  true,
	"MessageStatusNoPermission": true,
}

// errorOnlyLogged are handlers whose errors bridgev2 only logs (or never calls), so no message status
// is sent for them.
var errorOnlyLogged = map[string]bool{
	"HandleMatrixReadReceipt": true,
	"HandleMatrixTyping":      true,
	"HandleMatrixViewingChat": true,
}

func runMSS(pass *analysis.Pass) (any, error) {
	if len(pass.Files) == 0 {
		return nil, nil
	}
	if err := ConfigError(pass); err != nil {
		return nil, err
	}
	pi := infoFor(pass)
	cfg := ConfigFor(pass)
	ef := newErrFlow(pass, pi, cfg, cfg.StatusMappers).withFacts(pass, newMSSFact)
	if !pi.isBridge {
		return nil, nil
	}
	classifiers := findClassifiers(pi, cfg)

	for _, fd := range pi.funcsWithScope(ScopeMatrixHandler) {
		idx := errorResultIndex(funcType(pass.TypesInfo, fd))
		if idx < 0 {
			continue
		}
		if errorOnlyLogged[fd.Name.Name] {
			checkBlockingSends(pass, fd)
			continue
		}
		usesClassifier := callsAny(pass, pi, fd.Body, classifiers, 2)
		var firstRaw ast.Node
		ef.returnedErrors(fd, idx, func(ret *ast.ReturnStmt, o errOrigin) {
			switch o.kind {
			case errConstructed:
				if !o.hasCallee() {
					// A plain error that wraps nothing from the network is usually an internal
					// invariant; a generic failure status is fine for those.
					return
				}
				report(pass, ret, MSS001, fmt.Sprintf("%s returns %s; map the network error to a bridgev2.MessageStatus", fd.Name.Name, describeOrigin(pass.Fset, o)))
				if firstRaw == nil {
					firstRaw = ret
				}
			case errRaw:
				report(pass, ret, MSS001, fmt.Sprintf("%s returns %s; map it to a bridgev2.MessageStatus", fd.Name.Name, describeOrigin(pass.Fset, o)))
				if firstRaw == nil {
					firstRaw = ret
				}
			case errJoin:
				report(pass, ret, EP003, fmt.Sprintf("%s returns errors.Join; users see a multi-line raw error", fd.Name.Name))
			}
		})
		if firstRaw != nil && len(classifiers) > 0 && !usesClassifier {
			report(pass, firstRaw, MSS006, fmt.Sprintf("this package has %s but %s returns library errors without using it", strings.Join(classifierNames(classifiers), ", "), fd.Name.Name))
		}
		checkBlockingSends(pass, fd)
	}

	eachStatusChain(pi, func(c *statusChain) {
		checkStatusChain(pass, ef, c)
	})
	return nil, nil
}

func checkStatusChain(pass *analysis.Pass, ef *errFlow, c *statusChain) {
	info := pass.TypesInfo
	var innerOrigin errOrigin
	if c.inner != nil {
		innerOrigin = ef.classify(infoFor(pass).enclosingFunc(c.root), c.inner, c.root.Pos(), 1)
	}

	// MSS002
	if c.known && !c.hasStatus() {
		if reason, ok := c.reason(info); ok && permanentReasons[reason] {
			report(pass, c.node(), MSS002, fmt.Sprintf("status has ErrorReason %s but no WithStatus(event.MessageStatusFail), so clients offer a retry that can't work", reason))
		}
	}

	// MSS003
	if c.has("WithErrorAsMessage") {
		switch {
		case innerOrigin.kind == errRaw:
			report(pass, c.node(), MSS003, fmt.Sprintf("WithErrorAsMessage shows the %s to users; write a fixed human message with WithMessage", describeOrigin(pass.Fset, innerOrigin)))
		case innerOrigin.formatsErr:
			report(pass, c.node(), MSS003, "WithErrorAsMessage shows an error that formats another error or a status code; write a fixed human message with WithMessage")
		case innerOrigin.kind == errJoin:
			report(pass, c.node(), MSS003, "WithErrorAsMessage shows an errors.Join result to users")
		}
	}
	if m, ok := c.message(); ok && exprShowsError(pass.Pkg, info, m) {
		report(pass, m, MSS003, "status message is built from raw error text; use a fixed human string and keep the error as InternalError")
	}

	// MSS004 (partial): certain=true on a timeout
	if certain, ok := c.certain(info); ok && certain && c.inner != nil && mentionsTimeout(info, c.inner) {
		report(pass, c.node(), MSS004, "WithIsCertain(true) on a timeout; the message may have been sent, so certainty should be false")
	}

	// MSS005: WrapErrorInStatus defaults ErrorReason to GenericError, so only literals can leave it empty.
	if _, isLit := c.root.(*ast.CompositeLit); isLit {
		checkMissingReason(pass, c)
	}
}

func checkMissingReason(pass *analysis.Pass, c *statusChain) {
	info := pass.TypesInfo
	if _, hasMsg := c.message(); hasMsg {
		if _, hasCertain := c.certain(info); hasCertain || c.has("WithIsCertain") {
			if _, hasReason := c.reason(info); !hasReason {
				report(pass, c.node(), MSS005, "status sets a message and certainty but no ErrorReason; reasons drive checkpoints and analytics")
			}
		}
	}
}

// exprShowsError reports whether e turns an error into text: err.Error(), fmt.Sprint*(..., err).
func exprShowsError(pkg *types.Package, info *types.Info, e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found {
			return !found
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Error" && len(call.Args) == 0 && isErrorType(info.TypeOf(sel.X)) && !isLocalErrorType(pkg, info.TypeOf(sel.X)) {
			found = true
			return false
		}
		if isPkgFunc(calleeObj(info, call), "fmt", "Sprintf", "Sprint", "Sprintln") {
			for _, arg := range call.Args {
				if isErrorType(info.TypeOf(arg)) {
					found = true
					return false
				}
			}
		}
		return true
	})
	return found
}

// mentionsTimeout reports whether e is a timeout: one of the standard deadline sentinels, or a call to
// net.Error's Timeout method. A library's own timeout error isn't recognisable without being told, and
// guessing from the name of the variable holding it flagged unrelated code.
func mentionsTimeout(info *types.Info, e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			if obj := info.Uses[x.Sel]; obj != nil && obj.Pkg() != nil {
				if (obj.Pkg().Path() == "context" && obj.Name() == "DeadlineExceeded") || (obj.Pkg().Path() == "os" && obj.Name() == "ErrDeadlineExceeded") {
					found = true
				}
			}
		case *ast.CallExpr:
			if obj, ok := calleeObj(info, x).(*types.Func); ok && obj.Name() == "Timeout" && isNamed(recvType(obj), "net", "Error") {
				found = true
			}
		}
		return !found
	})
	return found
}

// findClassifiers returns package functions shaped func(error) string|int that call errors.As, plus configured ones.
func findClassifiers(pi *pkgInfo, cfg *Config) map[*types.Func]bool {
	out := map[*types.Func]bool{}
	configured := map[string]bool{}
	for _, name := range cfg.Classifiers {
		configured[name] = true
	}
	for obj, fd := range pi.decls {
		if configured[obj.Name()] {
			out[obj] = true
			continue
		}
		sig := obj.Type().(*types.Signature)
		if sig.Params().Len() != 1 || sig.Results().Len() < 1 || !isErrorInterface(sig.Params().At(0).Type()) {
			continue
		}
		basic, ok := sig.Results().At(0).Type().Underlying().(*types.Basic)
		if !ok || basic.Info()&(types.IsString|types.IsInteger) == 0 || !classifierNameRegex.MatchString(obj.Name()) {
			continue
		}
		callsAs := false
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok && isPkgFunc(calleeObj(pi.pass.TypesInfo, call), "errors", "As", "AsType") {
				callsAs = true
			}
			return !callsAs
		})
		if callsAs {
			out[obj] = true
		}
	}
	return out
}

func classifierNames(m map[*types.Func]bool) []string {
	var names []string
	for f := range m {
		names = append(names, f.Name())
	}
	sort.Strings(names)
	return names
}

func callsAny(pass *analysis.Pass, pi *pkgInfo, body ast.Node, fns map[*types.Func]bool, depth int) bool {
	if len(fns) == 0 || body == nil {
		return false
	}
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if f, ok := calleeObj(pass.TypesInfo, call).(*types.Func); ok && fns[f.Origin()] {
				found = true
			} else if depth > 0 {
				if fd := pi.declOf(call); fd != nil && callsAny(pass, pi, fd.Body, fns, depth-1) {
					found = true
				}
			}
		}
		return !found
	})
	return found
}

// checkBlockingSends implements GR007 for a Matrix handler.
func checkBlockingSends(pass *analysis.Pass, fd *ast.FuncDecl) {
	pi := infoFor(pass)
	inspectFunc(fd.Body, func(n ast.Node) bool {
		send, ok := n.(*ast.SendStmt)
		if !ok {
			return true
		}
		if parent, ok := pi.parents[send].(*ast.CommClause); ok && parent.Comm == send {
			if sel, ok := pi.parents[parent].(*ast.BlockStmt); ok {
				if ss, ok := pi.parents[sel].(*ast.SelectStmt); ok && selectHasDefault(ss) {
					return true
				}
			}
			if hasReceiveCase(pi, parent) {
				return true
			}
		}
		if ch, ok := pass.TypesInfo.TypeOf(send.Chan).Underlying().(*types.Chan); ok && ch != nil {
			report(pass, send, GR007, fmt.Sprintf("%s does a channel send that can block the portal event loop; use select with a default or ctx.Done() case", fd.Name.Name))
		}
		return true
	})
}

func selectHasDefault(ss *ast.SelectStmt) bool {
	for _, s := range ss.Body.List {
		if cc, ok := s.(*ast.CommClause); ok && cc.Comm == nil {
			return true
		}
	}
	return false
}

// hasReceiveCase reports whether the select around cc also waits on a receive, like ctx.Done(), a timer
// or a stop channel, so the send gives up instead of blocking forever.
func hasReceiveCase(pi *pkgInfo, cc *ast.CommClause) bool {
	block, ok := pi.parents[cc].(*ast.BlockStmt)
	if !ok {
		return false
	}
	for _, s := range block.List {
		other, ok := s.(*ast.CommClause)
		if !ok || other == cc || other.Comm == nil {
			continue
		}
		if _, isSend := other.Comm.(*ast.SendStmt); !isSend {
			return true
		}
	}
	return false
}

// isLocalErrorType reports whether t is a concrete error type declared in pkg. Its Error method is the
// bridge's own text (often a fixed user-facing notice), not a raw error from a library.
func isLocalErrorType(pkg *types.Package, t types.Type) bool {
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := t.(*types.Named)
	if !ok || types.IsInterface(named) {
		return false
	}
	return named.Obj().Pkg() == pkg
}
