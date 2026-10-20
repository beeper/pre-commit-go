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

var (
	eventTypeNameRegex = regexp.MustCompile(`(Event|Create|Update|Delete|Ready|Connect|Disconnect)$`)
	authCondRegex      = regexp.MustCompile(`(?i)\b40[13]\b|StatusUnauthorized|StatusForbidden|Unauthori[sz]ed|Forbidden|AuthError|InvalidAuth|BadCredentials`)
)

type stateLit struct {
	lit     *ast.CompositeLit
	qual    string
	fn      ast.Node
	fields  map[string]ast.Expr
	event   string
	code    string
	hasCode bool
	codeOK  bool // code is a constant
	action  string
}

func runBS(pass *analysis.Pass) (any, error) {
	if len(pass.Files) == 0 {
		return nil, nil
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
			}
		}
		return true
	})
}

func checkStateLit(pass *analysis.Pass, pi *pkgInfo, ef *errFlow, cfg *Config, sl *stateLit, keys map[string]bool, codeShape *regexp.Regexp) {
	info := pass.TypesInfo
	lit := sl.lit
	isErrorState := sl.event != "" && !slices.Contains([]string{"CONNECTED", "CONNECTING", "BACKFILLING", "STARTING", "RUNNING", "UNCONFIGURED"}, sl.event)

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
	if sl.event == "TRANSIENT_DISCONNECT" {
		if cond := enclosingCondText(pass, pi, lit); authCondRegex.MatchString(cond) {
			report(pass, lit, BS010, "TRANSIENT_DISCONNECT under an auth check; a rejected session won't recover by waiting, send BAD_CREDENTIALS")
		}
	}

	// BS011
	if sl.event == "BAD_CREDENTIALS" && isCatchAllAuth(pass, pi, ef, sl) {
		report(pass, lit, BS011, "BAD_CREDENTIALS sent for every connect error; only send it for errors that mean the session is invalid")
	}
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

func enclosingCondText(pass *analysis.Pass, pi *pkgInfo, n ast.Node) string {
	var parts []string
	for p := pi.parents[n]; p != nil; p = pi.parents[p] {
		switch x := p.(type) {
		case *ast.FuncDecl, *ast.FuncLit:
			return strings.Join(parts, " ")
		case *ast.IfStmt:
			if containsNode(x.Body, n) {
				parts = append(parts, nodeText(pass, x.Cond))
			}
		case *ast.CaseClause:
			for _, e := range x.List {
				parts = append(parts, nodeText(pass, e))
			}
		}
	}
	return strings.Join(parts, " ")
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

// isCatchAllAuth reports BAD_CREDENTIALS in a default/else branch, or directly under `if err != nil` after a connect call.
func isCatchAllAuth(pass *analysis.Pass, pi *pkgInfo, ef *errFlow, sl *stateLit) bool {
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
						if isErrorType(pass.TypesInfo.TypeOf(e)) || strings.Contains(nodeText(pass, e), "errors.Is") {
							mentionsErr = true
						}
					}
				}
				return !mentionsErr
			})
			return mentionsErr
		case *ast.IfStmt:
			if x.Else == child {
				cond := nodeText(pass, x.Cond)
				_, isBlock := x.Else.(*ast.BlockStmt)
				return isBlock && strings.Contains(cond, "err") && !authCondRegex.MatchString(cond)
			}
			if containsNode(x.Body, sl.lit) {
				if be, ok := x.Cond.(*ast.BinaryExpr); ok && be.Op == token.NEQ && isErrorInterface(pass.TypesInfo.TypeOf(be.X)) {
					o := ef.classify(sl.fn, be.X, x.Body.Pos(), 0)
					if o.kind == errRaw && strings.Contains(o.calleeFuncName(), "Connect") {
						return true
					}
				}
				return false
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
