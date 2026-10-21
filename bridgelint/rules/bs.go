package rules

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode"

	"golang.org/x/tools/go/analysis"
)

// humanKeysFact records the status.BridgeStateHumanErrors codes a package registers, so a code
// registered in one package counts in the packages that import it.
type humanKeysFact struct{ Keys []string }

func (*humanKeysFact) AFact() {}

func (f *humanKeysFact) String() string { return fmt.Sprintf("humanKeys%v", f.Keys) }

var BSAnalyzer = &analysis.Analyzer{
	Name: "bs",
	Doc:  "bridge state rules (BS001-BS011): states must carry the right event, action, code and human message, and failures must not be silent",
	Run:  runBS,

	Requires:  []*analysis.Analyzer{NetAnalyzer},
	FactTypes: []analysis.Fact{new(bsErrFact), new(humanKeysFact)},
}

// eventTypeNameRegex recognises a library's event types by name: nothing in their types marks them as
// events, so BS009 can only find the handler's type switch this way.
var eventTypeNameRegex = regexp.MustCompile(`(Event|Create|Update|Delete|Ready|Connect|Disconnect)$`)

type stateLit struct {
	lit  *ast.CompositeLit
	qual string
	fn   ast.Node
	// eventSetAt is where StateEvent got its value: the literal, or the later assignment that changed it.
	eventSetAt ast.Node
	fields     map[string]ast.Expr
	event      string
	code       string
	hasCode    bool
	codeOK     bool // code is a constant
	action     string
}

func runBS(pass *analysis.Pass) (any, error) {
	if len(pass.Files) == 0 {
		return nil, nil
	}
	if err := ConfigError(pass); err != nil {
		return nil, err
	}
	pi := infoFor(pass)
	keys := CollectHumanErrorKeys(pass.TypesInfo, pass.Files)
	if len(keys) > 0 {
		own := make([]string, 0, len(keys))
		for k := range keys {
			own = append(own, k)
		}
		sort.Strings(own)
		pass.ExportPackageFact(&humanKeysFact{Keys: own})
	}
	for _, pf := range pass.AllPackageFacts() {
		if hk, ok := pf.Fact.(*humanKeysFact); ok {
			for _, k := range hk.Keys {
				keys[k] = true
			}
		}
	}
	cfg := ConfigFor(pass)
	ef := newErrFlow(pass, pi, cfg).withFacts(pass, newBSFact)
	if !pi.isBridge {
		return nil, nil
	}
	codeShape := regexp.MustCompile(`^` + regexp.QuoteMeta(cfg.ErrorPrefix) + `-[a-z0-9-]+$`)

	for _, sl := range collectStateLits(pass, pi) {
		checkStateLit(pass, pi, ef, cfg, sl, keys, codeShape)
	}
	checkDisconnectEvents(pass, cfg)
	return nil, nil
}

// CollectHumanErrorKeys returns the codes registered in status.BridgeStateErrorMap literals and assignments.
func CollectHumanErrorKeys(info *types.Info, files []*ast.File) map[string]bool {
	keys := map[string]bool{}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CompositeLit:
				if isNamed(info.TypeOf(x), pathStatus, "BridgeStateErrorMap") {
					for _, elt := range x.Elts {
						if kv, ok := elt.(*ast.KeyValueExpr); ok {
							if s, ok := constString(info, kv.Key); ok {
								keys[s] = true
							}
						}
					}
				}
			case *ast.AssignStmt:
				for _, lhs := range x.Lhs {
					if idx, ok := lhs.(*ast.IndexExpr); ok && isNamed(info.TypeOf(idx.X), pathStatus, "BridgeStateErrorMap") {
						if s, ok := constString(info, idx.Index); ok {
							keys[s] = true
						}
					}
				}
			}
			return true
		})
	}
	return keys
}

func collectStateLits(pass *analysis.Pass, pi *pkgInfo) []*stateLit {
	var out []*stateLit
	info := pass.TypesInfo
	for _, f := range pass.Files {
		if isTestFile(pass, f) {
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok || !isNamed(info.TypeOf(lit), pathStatus, "BridgeState") {
				return true
			}
			if _, isPtr := info.TypeOf(lit).(*types.Pointer); isPtr {
				return true
			}
			sl := &stateLit{lit: lit, fn: pi.enclosingFunc(lit), fields: map[string]ast.Expr{}, qual: "status"}
			if sel, ok := lit.Type.(*ast.SelectorExpr); ok {
				if id, ok := sel.X.(*ast.Ident); ok {
					sl.qual = id.Name
				}
			}
			for _, elt := range lit.Elts {
				if kv, ok := elt.(*ast.KeyValueExpr); ok {
					if key, ok := kv.Key.(*ast.Ident); ok {
						sl.fields[key.Name] = kv.Value
					}
				}
			}
			sl.eventSetAt = lit
			mergeLaterAssignments(pass, pi, sl)
			if e, ok := sl.fields["StateEvent"]; ok {
				sl.event, _ = constString(info, e)
			}
			if e, ok := sl.fields["Error"]; ok {
				sl.hasCode = true
				sl.code, sl.codeOK = constString(info, e)
			}
			if e, ok := sl.fields["UserAction"]; ok {
				sl.action, _ = constString(info, e)
			}
			out = append(out, sl)
			return true
		})
	}
	return out
}

// mergeLaterAssignments folds `state.Field = x` assignments in the same function into the literal's fields.
func mergeLaterAssignments(pass *analysis.Pass, pi *pkgInfo, sl *stateLit) {
	var v types.Object
	switch p := pi.parents[sl.lit].(type) {
	case *ast.AssignStmt:
		for i, rhs := range p.Rhs {
			if rhs == sl.lit && i < len(p.Lhs) {
				if id, ok := p.Lhs[i].(*ast.Ident); ok {
					v = pass.TypesInfo.ObjectOf(id)
				}
			}
		}
	case *ast.ValueSpec:
		for i, val := range p.Values {
			if val == sl.lit && i < len(p.Names) {
				v = pass.TypesInfo.ObjectOf(p.Names[i])
			}
		}
	}
	if v == nil || sl.fn == nil {
		return
	}
	inspectFunc(funcBody(sl.fn), func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, lhs := range as.Lhs {
			sel, ok := lhs.(*ast.SelectorExpr)
			if !ok || i >= len(as.Rhs) {
				continue
			}
			if id, ok := sel.X.(*ast.Ident); ok && pass.TypesInfo.ObjectOf(id) == v {
				sl.fields[sel.Sel.Name] = as.Rhs[i]
				if sel.Sel.Name == "StateEvent" {
					sl.eventSetAt = as
				}
			}
		}
		return true
	})
}

func checkStateLit(pass *analysis.Pass, pi *pkgInfo, ef *errFlow, cfg *Config, sl *stateLit, keys map[string]bool, codeShape *regexp.Regexp) {
	info := pass.TypesInfo
	lit := sl.lit
	isErrorState := sl.event != "" && !slices.Contains([]string{"CONNECTED", "CONNECTING", "BACKFILLING", "STARTING", "RUNNING", "UNCONFIGURED", "LOGGED_OUT"}, sl.event)

	// BS001
	if sl.event == "BAD_CREDENTIALS" && sl.action == "RELOGIN" && FrameworkHas(FeatureReloginDefault) {
		report(pass, sl.fields["UserAction"], BS001, "BAD_CREDENTIALS already defaults to RELOGIN in bridgev2; the explicit UserAction is redundant")
	}

	// BS002
	if sl.codeOK && isRestrictionCode(sl.code) && sl.event != "" && !(sl.event == "BAD_CREDENTIALS" && (sl.action == "RESTART" || sl.action == "OPEN_NATIVE")) {
		report(pass, lit, BS002, fmt.Sprintf("%q looks like a restriction or ban but is sent as %s; restrictions are BAD_CREDENTIALS with UserAction RESTART (the user fixes it in the app or at a URL, then the bridge is restarted) or OPEN_NATIVE (the bridge recovers by itself once the user fixes it in the app)", sl.code, describeState(sl)))
	}

	// BS003
	if msg, ok := sl.fields["Message"]; ok && exprShowsError(info, msg) {
		var opts []reportOpt
		note := "move the raw error to Info[\"go_error\"] and write a human message"
		if sl.codeOK && keys[sl.code] {
			opts = append(opts, withSeverity(SeverityWarning))
			note = "the human-error map replaces it, so it's silently discarded; move it to Info[\"go_error\"]"
		}
		report(pass, msg, BS003, "bridge state Message is built from raw error text; "+note, opts...)
	}

	// BS004
	if isErrorState {
		switch {
		case !sl.hasCode:
			report(pass, lit, BS004, fmt.Sprintf("%s state has no Error code; give it a stable <net>-<reason> code", sl.event))
		case sl.codeOK && sl.code == "":
			report(pass, lit, BS004, fmt.Sprintf("%s state has an empty Error code", sl.event))
		case sl.codeOK && cfg.ErrorPrefix != "" && !codeShape.MatchString(sl.code):
			report(pass, sl.fields["Error"], BS004, fmt.Sprintf("code %q doesn't match %s-<reason>", sl.code, cfg.ErrorPrefix))
		case !sl.codeOK:
			if format, ok := sprintfFormat(info, sl.fields["Error"]); ok && !slices.Contains(cfg.CodeFormatAllowlist, format) {
				report(pass, sl.fields["Error"], BS004, fmt.Sprintf("code built with fmt.Sprintf(%q); codes must come from a bounded set (add the format to code_format_allowlist if it is)", format))
			}
		}
	}

	// BS005
	if isErrorState && sl.codeOK && sl.code != "" && !keys[sl.code] {
		if msg, ok := sl.fields["Message"]; !ok || isEmptyString(info, msg) {
			report(pass, lit, BS005, fmt.Sprintf("code %q has no Message and no status.BridgeStateHumanErrors entry", sl.code))
		}
	}

	if sl.fn == nil {
		return
	}

	// BS010
	if sl.event == "TRANSIENT_DISCONNECT" && authGuarded(pass, pi, cfg, sl.eventSetAt) {
		report(pass, lit, BS010, "TRANSIENT_DISCONNECT under an auth check; a rejected session won't recover by waiting, send BAD_CREDENTIALS")
	}

	// BS011. A state the code only upgrades to BAD_CREDENTIALS under an auth check is the right shape,
	// even though the literal it was built from sits under the bare error check.
	if sl.event == "BAD_CREDENTIALS" && !authGuarded(pass, pi, cfg, sl.eventSetAt) && isCatchAllAuth(pass, pi, ef, cfg, sl) {
		report(pass, lit, BS011, "BAD_CREDENTIALS sent for every connect error; only send it for errors that mean the session is invalid")
	}
}

func isErrorsIsCall(info *types.Info, e ast.Expr) bool {
	call, ok := unparen(e).(*ast.CallExpr)
	return ok && isPkgFunc(calleeObj(info, call), "errors", "Is", "As")
}

// condUsesError reports whether cond reads a variable that holds an error.
func condUsesError(info *types.Info, cond ast.Expr) bool {
	found := false
	ast.Inspect(cond, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok {
			if _, isVar := info.Uses[id].(*types.Var); isVar && isErrorType(info.TypeOf(id)) {
				found = true
			}
		}
		return !found
	})
	return found
}

// isNilCheck reports whether cond only compares an error with nil, which separates success from failure
// without telling errors apart.
func isNilCheck(info *types.Info, cond ast.Expr) bool {
	be, ok := unparen(cond).(*ast.BinaryExpr)
	return ok && (be.Op == token.EQL || be.Op == token.NEQ) && isErrorType(info.TypeOf(be.X)) && info.Types[be.Y].IsNil()
}

// comparesRawError reports whether cond is `err <op> ...` on an error returned unchanged by a network call.
func comparesRawError(pass *analysis.Pass, ef *errFlow, sl *stateLit, cond ast.Expr, op token.Token, at token.Pos) bool {
	be, ok := unparen(cond).(*ast.BinaryExpr)
	return ok && be.Op == op && isErrorInterface(pass.TypesInfo.TypeOf(be.X)) && ef.classify(sl.fn, be.X, at, 0).kind == errRaw
}

func describeState(sl *stateLit) string {
	if sl.action != "" {
		return sl.event + " with " + sl.action
	}
	return sl.event + " with no UserAction"
}

func containsNode(outer, inner ast.Node) bool {
	return inner.Pos() >= outer.Pos() && inner.End() <= outer.End()
}

func readFile(pass *analysis.Pass, name string) ([]byte, error) {
	if pass.ReadFile != nil {
		return pass.ReadFile(name)
	}
	return os.ReadFile(name)
}

func sprintfFormat(info *types.Info, e ast.Expr) (string, bool) {
	e = unparen(e)
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return "", false
	}
	if tv, ok := info.Types[call.Fun]; ok && tv.IsType() && len(call.Args) == 1 {
		return sprintfFormat(info, call.Args[0])
	}
	if !isPkgFunc(calleeObj(info, call), "fmt", "Sprintf") {
		return "", false
	}
	format, ok := stringArg(info, call, 0)
	if !ok {
		return "<dynamic>", true
	}
	return format, true
}

func isEmptyString(info *types.Info, e ast.Expr) bool {
	s, ok := constString(info, e)
	return ok && s == ""
}

// authGuarded reports whether n is only reached when the code has established that the session was
// rejected: it's in the branch of an if, or the case of a tagless switch, whose condition implies it.
func authGuarded(pass *analysis.Pass, pi *pkgInfo, cfg *Config, n ast.Node) bool {
	if n == nil {
		return false
	}
	for p := pi.parents[n]; p != nil; p = pi.parents[p] {
		switch x := p.(type) {
		case *ast.FuncDecl, *ast.FuncLit:
			return false
		case *ast.IfStmt:
			if containsNode(x.Body, n) && condImpliesAuth(pass, cfg, x.Cond, true) {
				return true
			}
			if x.Else != nil && containsNode(x.Else, n) && condImpliesAuth(pass, cfg, x.Cond, false) {
				return true
			}
		case *ast.CaseClause:
			if caseImpliesAuth(pass, pi, cfg, x) {
				return true
			}
		}
	}
	return false
}

// caseImpliesAuth reports whether every expression of a tagless switch case implies a rejected session.
func caseImpliesAuth(pass *analysis.Pass, pi *pkgInfo, cfg *Config, cc *ast.CaseClause) bool {
	sw, ok := pi.parents[pi.parents[cc]].(*ast.SwitchStmt)
	if !ok || sw.Tag != nil || len(cc.List) == 0 {
		return false
	}
	for _, e := range cc.List {
		if !condImpliesAuth(pass, cfg, e, true) {
			return false
		}
	}
	return true
}

// condImpliesAuth reports whether cond evaluating to want means the session was rejected, so that
// `code != 401` and `!errors.Is(err, ErrAuth)` guard their else branch rather than their body.
func condImpliesAuth(pass *analysis.Pass, cfg *Config, cond ast.Expr, want bool) bool {
	switch x := unparen(cond).(type) {
	case *ast.UnaryExpr:
		return x.Op == token.NOT && condImpliesAuth(pass, cfg, x.X, !want)
	case *ast.BinaryExpr:
		switch {
		case x.Op == token.LAND && want, x.Op == token.LOR && !want:
			return condImpliesAuth(pass, cfg, x.X, want) || condImpliesAuth(pass, cfg, x.Y, want)
		case x.Op == token.LOR && want, x.Op == token.LAND && !want:
			return condImpliesAuth(pass, cfg, x.X, want) && condImpliesAuth(pass, cfg, x.Y, want)
		case x.Op == token.EQL, x.Op == token.NEQ:
			return (x.Op == token.EQL) == want && (isAuthStatus(pass.TypesInfo, x.X) || isAuthStatus(pass.TypesInfo, x.Y))
		}
	case *ast.CallExpr:
		return want && isAuthErrorCheck(pass, cfg, x)
	}
	return false
}

// condChecksAuth reports whether cond tests for a rejected session either way: a comparison against
// HTTP 401 or 403, or errors.Is/As against one of the configured auth_errors.
func condChecksAuth(pass *analysis.Pass, cfg *Config, cond ast.Expr) bool {
	found := false
	ast.Inspect(cond, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.BinaryExpr:
			if (x.Op == token.EQL || x.Op == token.NEQ) && (isAuthStatus(pass.TypesInfo, x.X) || isAuthStatus(pass.TypesInfo, x.Y)) {
				found = true
			}
		case *ast.CallExpr:
			if isAuthErrorCheck(pass, cfg, x) {
				found = true
			}
		}
		return !found
	})
	return found
}

func isAuthStatus(info *types.Info, e ast.Expr) bool {
	v, ok := constInt(info, e)
	return ok && (v == 401 || v == 403)
}

// isAuthErrorCheck matches errors.Is/As against one of the configured auth_errors.
func isAuthErrorCheck(pass *analysis.Pass, cfg *Config, call *ast.CallExpr) bool {
	info := pass.TypesInfo
	if !isPkgFunc(calleeObj(info, call), "errors", "Is", "As") || len(call.Args) != 2 {
		return false
	}
	target := unparen(call.Args[1])
	if u, ok := target.(*ast.UnaryExpr); ok && u.Op == token.AND {
		target = unparen(u.X)
	}
	if sel, ok := target.(*ast.SelectorExpr); ok {
		target = sel.Sel
	}
	id, ok := target.(*ast.Ident)
	return ok && matchesQualified(info.Uses[id], cfg.AuthErrors)
}

// matchesQualified reports whether obj is named by one of names, each either a bare name or
// package-qualified ("slack.ErrInvalidAuth", by import path or package name).
func matchesQualified(obj types.Object, names []string) bool {
	if obj == nil {
		return false
	}
	for _, want := range names {
		i := strings.LastIndexByte(want, '.')
		if i < 0 {
			if obj.Name() == want {
				return true
			}
			continue
		}
		pkg, name := want[:i], want[i+1:]
		if obj.Name() == name && obj.Pkg() != nil && (obj.Pkg().Path() == pkg || obj.Pkg().Name() == pkg) {
			return true
		}
	}
	return false
}

func nodeText(pass *analysis.Pass, n ast.Node) string {
	start := pass.Fset.Position(n.Pos())
	end := pass.Fset.Position(n.End())
	data, err := readFile(pass, start.Filename)
	if err != nil || end.Offset > len(data) || start.Offset > end.Offset {
		return ""
	}
	return string(data[start.Offset:end.Offset])
}

// isCatchAllAuth reports BAD_CREDENTIALS in a default/else branch, or for any error from a connect call:
// directly under `if err != nil`, or in the else of `if err == nil`.
func isCatchAllAuth(pass *analysis.Pass, pi *pkgInfo, ef *errFlow, cfg *Config, sl *stateLit) bool {
	var child ast.Node = sl.lit
	for p := pi.parents[sl.lit]; p != nil; child, p = p, pi.parents[p] {
		switch x := p.(type) {
		case *ast.FuncDecl, *ast.FuncLit:
			return false
		case *ast.CaseClause:
			if x.List != nil {
				return false
			}
			sw, ok := pi.parents[pi.parents[x]].(*ast.SwitchStmt)
			if !ok {
				return false
			}
			mentionsErr := false
			ast.Inspect(sw.Body, func(n ast.Node) bool {
				if cc, ok := n.(*ast.CaseClause); ok {
					for _, e := range cc.List {
						if isErrorType(pass.TypesInfo.TypeOf(e)) || isErrorsIsCall(pass.TypesInfo, e) {
							mentionsErr = true
						}
					}
				}
				return !mentionsErr
			})
			return mentionsErr
		case *ast.IfStmt:
			if x.Else == child {
				if _, isBlock := x.Else.(*ast.BlockStmt); !isBlock {
					return false
				}
				if isNilCheck(pass.TypesInfo, x.Cond) {
					return comparesRawError(pass, ef, sl, x.Cond, token.EQL, x.Else.Pos())
				}
				return condUsesError(pass.TypesInfo, x.Cond) && !condChecksAuth(pass, cfg, x.Cond)
			}
			if containsNode(x.Body, sl.lit) {
				return comparesRawError(pass, ef, sl, x.Cond, token.NEQ, x.Body.Pos())
			}
		}
	}
	return false
}

// checkDisconnectEvents implements BS009.
func checkDisconnectEvents(pass *analysis.Pass, cfg *Config) {
	for path, wanted := range cfg.DisconnectEvents {
		var lib *types.Package
		for _, imp := range pass.Pkg.Imports() {
			if imp.Path() == path {
				lib = imp
			}
		}
		if lib == nil {
			continue
		}
		var switches []*ast.TypeSwitchStmt
		covered := map[string]bool{}
		for _, f := range pass.Files {
			ast.Inspect(f, func(n ast.Node) bool {
				ts, ok := n.(*ast.TypeSwitchStmt)
				if !ok {
					return true
				}
				fromLib := false
				for _, s := range ts.Body.List {
					cc := s.(*ast.CaseClause)
					for _, e := range cc.List {
						t := pass.TypesInfo.TypeOf(e)
						name := typeNameIn(t, lib)
						if name != "" {
							covered[name] = true
							if eventTypeNameRegex.MatchString(name) || slices.Contains(wanted, name) {
								fromLib = true
							}
						}
					}
				}
				if fromLib {
					switches = append(switches, ts)
				}
				return true
			})
		}
		if len(switches) == 0 {
			continue
		}
		for _, w := range wanted {
			if !covered[w] {
				report(pass, switches[0], BS009, fmt.Sprintf("event handler for %s has no case for %s; a dropped connection goes unnoticed", lib.Name(), w))
			}
		}
	}
}

func typeNameIn(t types.Type, pkg *types.Package) string {
	if t == nil {
		return ""
	}
	prefix := ""
	if p, ok := t.(*types.Pointer); ok {
		prefix = "*"
		t = p.Elem()
	}
	n, ok := types.Unalias(t).(*types.Named)
	if !ok || n.Obj().Pkg() != pkg {
		return ""
	}
	return prefix + n.Obj().Name()
}

// restrictionWords are the whole words in a state code (split on anything that isn't a letter or digit)
// that mark an account restriction the user fixes on the network.
var restrictionWords = map[string]bool{
	"ban": true, "banned": true, "suspend": true, "suspended": true, "suspension": true,
	"restrict": true, "restricted": true, "restriction": true, "lock": true, "locked": true,
	"lockout": true, "checkpoint": true, "consent": true, "challenge": true, "disabled": true,
	"deactivate": true, "deactivated": true,
}

// restrictionPhrases are adjacent word pairs with the same meaning.
var restrictionPhrases = [][2]string{{"access", "denied"}, {"not", "offered"}}

func codeWords(code string) []string {
	return strings.FieldsFunc(strings.ToLower(code), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
}

func hasCodeWord(code string, words map[string]bool) bool {
	for _, w := range codeWords(code) {
		if words[w] {
			return true
		}
	}
	return false
}

func isRestrictionCode(code string) bool {
	if hasCodeWord(code, restrictionWords) {
		return true
	}
	words := codeWords(code)
	for i := 0; i+1 < len(words); i++ {
		for _, p := range restrictionPhrases {
			if words[i] == p[0] && words[i+1] == p[1] {
				return true
			}
		}
	}
	return false
}
