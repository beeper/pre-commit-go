package rules

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/types"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"
)

var LPAnalyzer = &analysis.Analyzer{
	Name: "lp",
	Doc:  "login and provisioning rules (LP001-LP008): failures must be RespErrors with HTTP statuses that clients won't retry automatically",
	Run:  runLP,

	FactTypes: []analysis.Fact{new(lpErrFact)},
}

var (
	rateLimitRegex = regexp.MustCompile(`(?i)rate.?limit|too many (requests|attempts|tries)|flood|slow ?down`)
	// userInputRegex matches plain login/provisioning errors that describe bad user input, which should be 4xx.
	// Other plain errors are treated as internal invariants and not reported.
	// flowRegex matches CreateLogin errors about the flow ID, which comes straight from the client.
	// Other plain errors can't be told apart from internal invariants by their text, so they aren't reported.
	flowRegex = regexp.MustCompile(`(?i)\bflow\b`)
)

// autoRetriedStatuses are the HTTP statuses that clients (mautrix-go's retryafter.Should, and the Beeper
// clients) retry automatically. Login and provisioning requests must not be retried behind the user's back.
var autoRetriedStatuses = map[int64]bool{429: true, 502: true, 503: true, 504: true}

const (
	lp002Msg = "rate limit RespError is sent as HTTP 429, which clients retry automatically; use 400 (the M_LIMIT_EXCEEDED code still says it's a rate limit)"
	lp003Fmt = "RespError is sent as HTTP %d, which clients retry automatically; use 500 for upstream failures or a 4xx for rejections"
)

// standardCodes maps standard Matrix error codes to their mautrix.RespError variables and default statuses.
var standardCodes = map[string]struct {
	name   string
	status int
}{
	"M_UNKNOWN":                   {"MUnknown", 500},
	"M_FORBIDDEN":                 {"MForbidden", 403},
	"M_UNRECOGNIZED":              {"MUnrecognized", 404},
	"M_UNKNOWN_TOKEN":             {"MUnknownToken", 401},
	"M_MISSING_TOKEN":             {"MMissingToken", 401},
	"M_BAD_JSON":                  {"MBadJSON", 400},
	"M_NOT_JSON":                  {"MNotJSON", 400},
	"M_NOT_FOUND":                 {"MNotFound", 404},
	"M_LIMIT_EXCEEDED":            {"MLimitExceeded", 429},
	"M_USER_DEACTIVATED":          {"MUserDeactivated", 0},
	"M_USER_IN_USE":               {"MUserInUse", 400},
	"M_INVALID_USERNAME":          {"MInvalidUsername", 400},
	"M_ROOM_IN_USE":               {"MRoomInUse", 400},
	"M_BAD_STATE":                 {"MBadState", 0},
	"M_TOO_LARGE":                 {"MTooLarge", 413},
	"M_EXCLUSIVE":                 {"MExclusive", 400},
	"M_UNSUPPORTED_ROOM_VERSION":  {"MUnsupportedRoomVersion", 0},
	"M_INCOMPATIBLE_ROOM_VERSION": {"MIncompatibleRoomVersion", 0},
	"M_INVALID_PARAM":             {"MInvalidParam", 400},
	"M_WRONG_ROOM_KEYS_VERSION":   {"MWrongRoomKeysVersion", 403},
	"M_URL_NOT_SET":               {"MURLNotSet", 0},
	"M_BAD_STATUS":                {"MBadStatus", 0},
	"M_CONNECTION_TIMEOUT":        {"MConnectionTimeout", 0},
	"M_CONNECTION_FAILED":         {"MConnectionFailed", 0},
}

func isRespErrorType(t types.Type) bool {
	return isNamed(t, pathBridgev2, "RespError") || isNamed(t, pathMautrix, "RespError")
}

type respErr struct {
	node       ast.Node
	lit        *ast.CompositeLit
	fields     map[string]ast.Expr
	code       string
	codeKnown  bool
	msg        string
	status     ast.Expr
	statusVal  int64
	statusKnow bool
}

func runLP(pass *analysis.Pass) (any, error) {
	if len(pass.Files) == 0 {
		return nil, nil
	}
	pi := infoFor(pass)
	cfg := ConfigFor(pass)
	ef := newErrFlow(pi, cfg, cfg.LoginMappers).withFacts(pass, newLPFact)
	if !pi.isBridge {
		return nil, nil
	}
	info := pass.TypesInfo

	for _, fd := range pi.funcsWithScope(ScopeLogin | ScopeProvisioning) {
		idx := errorResultIndex(funcType(info, fd))
		if idx < 0 {
			continue
		}
		ef.returnedErrors(fd, idx, func(ret *ast.ReturnStmt, o errOrigin) {
			if o.kind == errRaw || o.kind == errConstructed && (o.hasCallee() || isUnknownFlowError(pi, fd, o)) {
				report(pass, ret, LP001, fmt.Sprintf("%s returns %s, which reaches clients as a bare 500 M_UNKNOWN; return a bridgev2.RespError with a matching status (or wrap with bridgev2.WrapRespErr)", fd.Name.Name, describeOrigin(pass.Fset, o)))
			}
		})
		if pi.scopes[fd]&ScopeLogin != 0 {
			checkDuplicateValidation(pass, pi, fd)
		}
	}

	for _, f := range pass.Files {
		if isTestFile(pass, f) {
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CompositeLit:
				if isRespErrorType(info.TypeOf(x)) {
					checkRespErrLit(pass, pi, f, x)
				}
			case *ast.CallExpr:
				checkRespErrCall(pass, pi, f, x)
			case *ast.SelectorExpr:
				checkDefaultLimitExceeded(pass, pi, f, x)
			}
			return true
		})
	}
	return nil, nil
}

func parseRespErrLit(info *types.Info, lit *ast.CompositeLit) *respErr {
	re := &respErr{node: lit, lit: lit, fields: map[string]ast.Expr{}}
	for _, elt := range lit.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			if key, ok := kv.Key.(*ast.Ident); ok {
				re.fields[key.Name] = kv.Value
			}
		}
	}
	if e, ok := re.fields["ErrCode"]; ok {
		re.code, re.codeKnown = constString(info, e)
		if !re.codeKnown {
			if name, ok := standardVarSelector(info, e); ok {
				for code, sc := range standardCodes {
					if sc.name == name {
						re.code, re.codeKnown = code, true
					}
				}
			}
		}
	}
	if e, ok := re.fields["Err"]; ok {
		re.msg, _ = constString(info, e)
	}
	if e, ok := re.fields["StatusCode"]; ok {
		re.status = e
		re.statusVal, re.statusKnow = constInt(info, e)
	}
	return re
}

// standardVarSelector matches mautrix.MLimitExceeded.ErrCode and returns "MLimitExceeded".
func standardVarSelector(info *types.Info, e ast.Expr) (string, bool) {
	sel, ok := unparen(e).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "ErrCode" {
		return "", false
	}
	inner, ok := sel.X.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	obj := info.Uses[inner.Sel]
	if obj == nil || obj.Pkg() == nil || obj.Pkg().Path() != pathMautrix {
		return "", false
	}
	return obj.Name(), true
}

func checkRespErrLit(pass *analysis.Pass, pi *pkgInfo, file *ast.File, lit *ast.CompositeLit) {
	info := pass.TypesInfo
	re := parseRespErrLit(info, lit)
	isRate := re.code == "M_LIMIT_EXCEEDED" || rateLimitRegex.MatchString(re.msg) || rateLimitRegex.MatchString(re.code)

	// LP002, LP003
	if re.statusKnow && autoRetriedStatuses[re.statusVal] && !isTrue(info, re.fields["CanRetry"]) && !explicitlyRetriable(pi, info, lit) {
		if isRate && re.statusVal == 429 {
			report(pass, re.status, LP002, lp002Msg, withFix("Use 400", analysis.TextEdit{Pos: re.status.Pos(), End: re.status.End(), NewText: []byte(statusBadRequest(file))}))
		} else {
			report(pass, re.status, LP003, fmt.Sprintf(lp003Fmt, re.statusVal))
		}
	}

	// LP004
	if re.status != nil && !re.statusKnow && isPassthroughStatus(info, re.status) {
		report(pass, re.status, LP004, "HTTP status copied from a network error code; map it to a fixed status (400 with M_LIMIT_EXCEEDED for rate limits, 401/403 for auth, 500 for upstream)")
	}

	// LP005
	if re.status == nil && !parentCallsWithStatus(pi, lit) && pass.Pkg.Path() != pathMautrix {
		report(pass, lit, LP005, "RespError literal without StatusCode is sent as 500; set the status that matches the cause")
	}

	// LP007
	if sc, ok := standardCodes[re.code]; ok && re.codeKnown {
		msg := fmt.Sprintf("RespError literal for %s; use mautrix.%s.WithMessage(...) so the status can't drift from the code", re.code, sc.name)
		var opts []reportOpt
		if fix, ok := lp007Fix(pass, file, re, sc.name, sc.status); ok {
			opts = append(opts, fix)
		}
		report(pass, lit, LP007, msg, opts...)
	}
}

func parentCallsWithStatus(pi *pkgInfo, lit *ast.CompositeLit) bool {
	sel, ok := pi.parents[lit].(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "WithStatus"
}

func statusBadRequest(file *ast.File) string {
	if name, ok := importName(file, "net/http"); ok {
		return name + ".StatusBadRequest"
	}
	return "400"
}

func importName(file *ast.File, path string) (string, bool) {
	for _, imp := range file.Imports {
		p, _ := strconv.Unquote(imp.Path.Value)
		if p != path {
			continue
		}
		if imp.Name != nil {
			return imp.Name.Name, true
		}
		return path[strings.LastIndexByte(path, '/')+1:], true
	}
	return "", false
}

func lp007Fix(pass *analysis.Pass, file *ast.File, re *respErr, varName string, defaultStatus int) (reportOpt, bool) {
	for name := range re.fields {
		if name != "ErrCode" && name != "Err" && name != "StatusCode" {
			return nil, false
		}
	}
	mautrixName, ok := importName(file, pathMautrix)
	if !ok {
		return nil, false
	}
	var b strings.Builder
	b.WriteString(mautrixName + "." + varName)
	if e, ok := re.fields["Err"]; ok {
		b.WriteString(".WithMessage(" + nodeText(pass, e) + ")")
	}
	if re.status != nil && !(re.statusKnow && re.statusVal == int64(defaultStatus)) {
		b.WriteString(".WithStatus(" + nodeText(pass, re.status) + ")")
	}
	text := b.String()
	if isNamed(pass.TypesInfo.TypeOf(re.lit), pathBridgev2, "RespError") {
		bridgeName, ok := importName(file, pathBridgev2)
		if !ok {
			return nil, false
		}
		text = bridgeName + ".RespError(" + text + ")"
	}
	return withFix("Use mautrix."+varName, analysis.TextEdit{Pos: re.lit.Pos(), End: re.lit.End(), NewText: []byte(text)}), true
}

func isPassthroughStatus(info *types.Info, e ast.Expr) bool {
	e = unparen(e)
	if call, ok := e.(*ast.CallExpr); ok {
		if tv, ok := info.Types[call.Fun]; ok && tv.IsType() && len(call.Args) == 1 {
			e = unparen(call.Args[0])
		}
	}
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	name := strings.ToLower(sel.Sel.Name)
	return strings.Contains(name, "code") || strings.Contains(name, "status")
}

// checkRespErrCall handles mautrix.MX.WithStatus(...) chains and WrapRespErrManual (LP002, LP003, LP004).
func checkRespErrCall(pass *analysis.Pass, pi *pkgInfo, file *ast.File, call *ast.CallExpr) {
	info := pass.TypesInfo
	if isPkgFunc(calleeObj(info, call), pathBridgev2, "WrapRespErrManual") && len(call.Args) == 3 {
		code, _ := constString(info, call.Args[1])
		if v, ok := constInt(info, call.Args[2]); ok {
			checkStatusArg(pass, file, call.Args[2], v, code == "M_LIMIT_EXCEEDED" || rateLimitRegex.MatchString(code))
		} else if isPassthroughStatus(info, call.Args[2]) {
			report(pass, call.Args[2], LP004, "HTTP status copied from a network error code; map it to a fixed status")
		}
		return
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "WithStatus" || len(call.Args) != 1 || !isRespErrorType(info.TypeOf(sel.X)) {
		return
	}
	v, known := constInt(info, call.Args[0])
	if !known {
		if isPassthroughStatus(info, call.Args[0]) {
			report(pass, call.Args[0], LP004, "HTTP status copied from a network error code; map it to a fixed status")
		}
		return
	}
	if explicitlyRetriable(pi, info, call) {
		return
	}
	isRate := false
	ast.Inspect(sel.X, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && id.Name == "MLimitExceeded" {
			isRate = true
		}
		if lit, ok := n.(*ast.BasicLit); ok && rateLimitRegex.MatchString(lit.Value) {
			isRate = true
		}
		return !isRate
	})
	checkStatusArg(pass, file, call.Args[0], v, isRate)
}

func checkStatusArg(pass *analysis.Pass, file *ast.File, arg ast.Expr, v int64, isRate bool) {
	if !autoRetriedStatuses[v] {
		return
	}
	if isRate && v == 429 {
		report(pass, arg, LP002, lp002Msg, withFix("Use 400", analysis.TextEdit{Pos: arg.Pos(), End: arg.End(), NewText: []byte(statusBadRequest(file))}))
	} else {
		report(pass, arg, LP003, fmt.Sprintf(lp003Fmt, v))
	}
}

// checkDefaultLimitExceeded implements LP002 for mautrix.MLimitExceeded used as a RespError without
// WithStatus, which keeps its default status of 429. Plain references (errors.Is targets) aren't reported.
func checkDefaultLimitExceeded(pass *analysis.Pass, pi *pkgInfo, file *ast.File, sel *ast.SelectorExpr) {
	obj := pass.TypesInfo.Uses[sel.Sel]
	if obj == nil || obj.Pkg() == nil || obj.Pkg().Path() != pathMautrix || obj.Name() != "MLimitExceeded" {
		return
	}
	var outer ast.Expr = sel
	methods := 0
	for {
		ps, ok := pi.parents[outer].(*ast.SelectorExpr)
		if !ok || ps.X != outer {
			break
		}
		call, ok := pi.parents[ps].(*ast.CallExpr)
		if !ok || call.Fun != ps {
			break
		}
		if ps.Sel.Name == "WithStatus" {
			return
		}
		methods++
		outer = call
	}
	converted := false
	if call, ok := pi.parents[outer].(*ast.CallExpr); ok && len(call.Args) == 1 && call.Args[0] == outer {
		if tv, ok := pass.TypesInfo.Types[call.Fun]; ok && tv.IsType() {
			converted = true
		}
	}
	if methods == 0 && !converted || explicitlyRetriable(pi, pass.TypesInfo, outer) {
		return
	}
	report(pass, outer, LP002, "mautrix.MLimitExceeded is sent as HTTP 429 by default, which clients retry automatically; add WithStatus(400)",
		withFix("Use 400", analysis.TextEdit{Pos: outer.End(), End: outer.End(), NewText: []byte(".WithStatus(" + statusBadRequest(file) + ")")}))
}

func isUnknownFlowError(pi *pkgInfo, fd *ast.FuncDecl, o errOrigin) bool {
	return fd.Name.Name == "CreateLogin" && pi.scopes[fd]&ScopeLogin != 0 && flowRegex.MatchString(o.msg)
}

// checkDuplicateValidation implements LP008.
func checkDuplicateValidation(pass *analysis.Pass, pi *pkgInfo, fd *ast.FuncDecl) {
	patterns := loginFieldPatterns(pass)
	if len(patterns) == 0 {
		return
	}
	info := pass.TypesInfo
	ef := newErrFlow(pi, ConfigFor(pass))
	inspectFunc(fd.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		var pattern string
		var found bool
		obj := calleeObj(info, call)
		switch {
		case isPkgFunc(obj, "regexp", "MatchString") && len(call.Args) == 2:
			pattern, found = constString(info, call.Args[0])
		case obj != nil && obj.Name() == "MatchString" && isNamed(recvType(obj), "regexp", "Regexp"):
			pattern, found = regexpPattern(info, ef, call.Fun.(*ast.SelectorExpr).X)
		}
		if found && patterns[pattern] {
			report(pass, call, LP008, "this check duplicates the Pattern on the login field; drop it and let step validation handle the input")
		}
		return true
	})
}

func recvType(obj types.Object) types.Type {
	f, ok := obj.(*types.Func)
	if !ok {
		return nil
	}
	sig := f.Type().(*types.Signature)
	if sig.Recv() == nil {
		return nil
	}
	return sig.Recv().Type()
}

func regexpPattern(info *types.Info, ef *errFlow, e ast.Expr) (string, bool) {
	e = unparen(e)
	switch x := e.(type) {
	case *ast.CallExpr:
		if isPkgFunc(calleeObj(info, x), "regexp", "MustCompile") {
			return stringArg(info, x, 0)
		}
	case *ast.Ident, *ast.SelectorExpr:
		var id *ast.Ident
		if s, ok := x.(*ast.SelectorExpr); ok {
			id = s.Sel
		} else {
			id = x.(*ast.Ident)
		}
		if v, ok := info.Uses[id].(*types.Var); ok && v.Pkg() == ef.pi.pass.Pkg && v.Parent() == v.Pkg().Scope() {
			if init := ef.pkgVarInit(v); init != nil {
				return regexpPattern(info, ef, init)
			}
		}
	}
	return "", false
}

func loginFieldPatterns(pass *analysis.Pass) map[string]bool {
	out := map[string]bool{}
	for _, f := range pass.Files {
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			t := pass.TypesInfo.TypeOf(lit)
			if !isNamed(t, pathBridgev2, "LoginInputDataField") && !isNamed(t, pathBridgev2, "LoginCookieField") {
				return true
			}
			for _, elt := range lit.Elts {
				if kv, ok := elt.(*ast.KeyValueExpr); ok {
					if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "Pattern" {
						if s, ok := constString(pass.TypesInfo, kv.Value); ok && s != "" {
							out[s] = true
						} else if call, ok := unparen(kv.Value).(*ast.CallExpr); ok {
							if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "String" {
								ef := newErrFlow(infoFor(pass), ConfigFor(pass))
								if s, ok := regexpPattern(pass.TypesInfo, ef, sel.X); ok {
									out[s] = true
								}
							}
						}
					}
				}
			}
			return true
		})
	}
	return out
}

// explicitlyRetriable reports whether the RespError expression e is part of a method chain that calls
// WithCanRetry(true). That marks a deliberate retry (e.g. direct media waiting on a phone), not a
// provisioning failure.
func explicitlyRetriable(pi *pkgInfo, info *types.Info, e ast.Expr) bool {
	isCanRetry := func(call *ast.CallExpr, sel *ast.SelectorExpr) bool {
		return sel.Sel.Name == "WithCanRetry" && len(call.Args) == 1 && isTrue(info, call.Args[0])
	}
	var outer ast.Expr = e
	for {
		ps, ok := pi.parents[outer].(*ast.SelectorExpr)
		if !ok || ps.X != outer {
			break
		}
		call, ok := pi.parents[ps].(*ast.CallExpr)
		if !ok || call.Fun != ps {
			break
		}
		if isCanRetry(call, ps) {
			return true
		}
		outer = call
	}
	for cur := e; ; {
		call, ok := unparen(cur).(*ast.CallExpr)
		if !ok {
			return false
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		if isCanRetry(call, sel) {
			return true
		}
		cur = sel.X
	}
}

func isTrue(info *types.Info, e ast.Expr) bool {
	if e == nil {
		return false
	}
	tv, ok := info.Types[e]
	return ok && tv.Value != nil && tv.Value.Kind() == constant.Bool && constant.BoolVal(tv.Value)
}
