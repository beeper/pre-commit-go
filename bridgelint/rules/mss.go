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
}

var permanentRegex = regexp.MustCompile(`(?i)not supported|unsupported|(doesn't|does not|don't|do not) support|too (large|long|big)|exceeds the|only (your|their) own|not allowed|(can't|cannot) be (sent|edited|deleted|used)`)

var classifierNameRegex = regexp.MustCompile(`(?i)(code|kind|class|reason|status)`)

var permanentReasons = map[string]bool{
	"MessageStatusUnsupported":  true,
	"MessageStatusNoPermission": true,
	"MessageStatusTooOld":       true,
}

func runMSS(pass *analysis.Pass) (any, error) {
	pi := infoFor(pass)
	checkIgnores(pass)
	if !pi.isBridge {
		return nil, nil
	}
	cfg := ConfigFor(pass)
	ef := newErrFlow(pi, cfg, cfg.StatusMappers)
	classifiers := findClassifiers(pi, cfg)

	for _, fd := range pi.funcsWithScope(ScopeMatrixHandler) {
		idx := errorResultIndex(funcType(pass.TypesInfo, fd))
		if idx < 0 {
			continue
		}
		usesClassifier := callsAny(pass, pi, fd.Body, classifiers, 2)
		var firstRaw ast.Node
		ef.returnedErrors(fd, idx, func(ret *ast.ReturnStmt, o errOrigin) {
			switch o.kind {
			case errConstructed:
				if o.msg != "" && permanentRegex.MatchString(o.msg) {
					report(pass, ret, MSS002, fmt.Sprintf("%s returns %s, which reads as permanent but becomes a retriable status; return a bridgev2.Err* sentinel or WrapErrorInStatus(...).WithStatus(event.MessageStatusFail) with an ErrorReason", fd.Name.Name, describeOrigin(pass.Fset, o)))
					return
				}
				if o.callee == nil {
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
		reason, hasReason := c.reason(info)
		var msg string
		if m, ok := c.message(); ok {
			msg, _ = constString(info, m)
		} else if innerOrigin.kind == errConstructed {
			msg = innerOrigin.msg
		}
		switch {
		case hasReason && permanentReasons[reason]:
			report(pass, c.node(), MSS002, fmt.Sprintf("status has ErrorReason %s but no WithStatus(event.MessageStatusFail), so clients offer a retry that can't work", reason))
		case msg != "" && permanentRegex.MatchString(msg) && !(hasReason && (reason == "MessageStatusNetworkError" || reason == "MessageStatusBridgeUnavailable")):
			report(pass, c.node(), MSS002, fmt.Sprintf("status %q reads as permanent but stays retriable; add WithStatus(event.MessageStatusFail) and an ErrorReason, or use a bridgev2.Err* sentinel", msg))
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
	if m, ok := c.message(); ok && exprShowsError(info, m) {
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
func exprShowsError(info *types.Info, e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found {
			return !found
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Error" && len(call.Args) == 0 && isErrorType(info.TypeOf(sel.X)) {
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
			if strings.Contains(strings.ToLower(x.Sel.Name), "timedout") || strings.Contains(strings.ToLower(x.Sel.Name), "timeout") {
				found = true
			}
		case *ast.Ident:
			if strings.Contains(strings.ToLower(x.Name), "timeout") || strings.Contains(strings.ToLower(x.Name), "timedout") {
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
			if hasCtxDoneCase(pi, parent) {
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

func hasCtxDoneCase(pi *pkgInfo, cc *ast.CommClause) bool {
	block, ok := pi.parents[cc].(*ast.BlockStmt)
	if !ok {
		return false
	}
	for _, s := range block.List {
		other, ok := s.(*ast.CommClause)
		if !ok || other == cc || other.Comm == nil {
			continue
		}
		found := false
		ast.Inspect(other.Comm, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "Done" {
				found = true
			}
			return !found
		})
		if found {
			return true
		}
	}
	return false
}
