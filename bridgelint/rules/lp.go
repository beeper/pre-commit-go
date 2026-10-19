package rules

import (
	"fmt"
	"go/ast"
	"go/types"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"
)

var LPAnalyzer = &analysis.Analyzer{
	Name: "lp",
	Doc:  "login and provisioning rules (LP001-LP008): user-caused failures must be RespErrors with matching HTTP statuses",
	Run:  runLP,
}

var (
	rateLimitRegex = regexp.MustCompile(`(?i)rate.?limit|too many requests|flood|slow ?down`)
	// userInputRegex matches plain login/provisioning errors that describe bad user input, which should be 4xx.
	// Other plain errors are treated as internal invariants and not reported.
	userInputRegex     = regexp.MustCompile(`(?i)\b(required|empty|missing|invalid|not found|no \w+( \w+)? (found|matched)|multiple \w+( \w+)? matched|must|too (few|many|long|short)|at least|unknown (login )?flow)\b`)
	temporaryRegex     = regexp.MustCompile(`(?i)temporar|unavailable|outage|try again later`)
	temporaryCodeRegex = regexp.MustCompile(`(?i)temporar|outage`)
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
	pi := infoFor(pass)
	if !pi.isBridge {
		return nil, nil
	}
	cfg := ConfigFor(pass)
	ef := newErrFlow(pi, cfg, cfg.LoginMappers)
	info := pass.TypesInfo

	for _, fd := range pi.funcsWithScope(ScopeLogin | ScopeProvisioning) {
		idx := errorResultIndex(funcType(info, fd))
		if idx < 0 {
			continue
		}
		ef.returnedErrors(fd, idx, func(ret *ast.ReturnStmt, o errOrigin) {
			if o.kind == errRaw || o.kind == errConstructed && (o.callee != nil || userInputRegex.MatchString(o.msg)) {
				report(pass, ret, LP001, fmt.Sprintf("%s returns %s, which reaches clients as a bare 500 M_UNKNOWN; return a bridgev2.RespError with a matching status (or wrap with bridgev2.WrapRespErr)", fd.Name.Name, describeOrigin(pass.Fset, o)))
			}
		})
		if pi.scopes[fd]&ScopeProvisioning != 0 {
			checkSwallowed(pass, fd)
		}
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
				checkRespErrCall(pass, x)
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

	// LP002
	lp002 := isRate && re.status != nil && re.statusKnow && re.statusVal != 429
	if lp002 {
		report(pass, re.status, LP002, fmt.Sprintf("rate limit returned as HTTP %d; use 429", re.statusVal), withFix("Use 429", analysis.TextEdit{Pos: re.status.Pos(), End: re.status.End(), NewText: []byte(statusTooManyRequests(file))}))
	} else if isRate && re.status == nil && !parentCallsWithStatus(pi, lit) {
		report(pass, lit, LP002, "rate limit RespError has no StatusCode, so it's sent as 500; use 429")
	}

	// LP003
	isRestriction := restrictionRegex.MatchString(re.msg) || restrictionRegex.MatchString(re.code)
	if !lp002 && !isRestriction && re.statusKnow && re.statusVal >= 400 && re.statusVal < 500 && re.statusVal != 429 && (temporaryRegex.MatchString(re.msg) || temporaryCodeRegex.MatchString(re.code)) {
		report(pass, re.status, LP003, fmt.Sprintf("temporary or upstream failure returned as HTTP %d; use 502 or 503", re.statusVal))
	}

	// LP004
	if re.status != nil && !re.statusKnow && isPassthroughStatus(info, re.status) {
		report(pass, re.status, LP004, "HTTP status copied from a network error code; map it to a fixed status (429 for rate limits, 401/403 for auth, 502/503 for upstream)")
	}

	// LP005
	if re.status == nil && !isRate && !parentCallsWithStatus(pi, lit) && pass.Pkg.Path() != pathMautrix {
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

func statusTooManyRequests(file *ast.File) string {
	for _, imp := range file.Imports {
		if imp.Path.Value == `"net/http"` {
			if imp.Name != nil {
				return imp.Name.Name + ".StatusTooManyRequests"
			}
			return "http.StatusTooManyRequests"
		}
	}
	return "429"
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

// checkRespErrCall handles mautrix.MX.WithStatus(...) chains and WrapRespErrManual (LP002, LP004).
func checkRespErrCall(pass *analysis.Pass, call *ast.CallExpr) {
	info := pass.TypesInfo
	if isPkgFunc(calleeObj(info, call), pathBridgev2, "WrapRespErrManual") && len(call.Args) == 3 {
		code, _ := constString(info, call.Args[1])
		if v, ok := constInt(info, call.Args[2]); ok && (code == "M_LIMIT_EXCEEDED" || rateLimitRegex.MatchString(code)) && v != 429 {
			report(pass, call.Args[2], LP002, fmt.Sprintf("rate limit returned as HTTP %d; use 429", v))
		} else if !ok && isPassthroughStatus(info, call.Args[2]) {
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
	if v == 429 {
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
	if isRate {
		report(pass, call.Args[0], LP002, fmt.Sprintf("rate limit returned as HTTP %d; use 429", v))
	}
}

// checkSwallowed implements LP006.
func checkSwallowed(pass *analysis.Pass, fd *ast.FuncDecl) {
	inspectFunc(fd.Body, func(n ast.Node) bool {
		ifs, ok := n.(*ast.IfStmt)
		if !ok || !isErrNilCheck(pass, ifs.Cond) || ifs.Else != nil {
			return true
		}
		logged := false
		for _, s := range ifs.Body.List {
			es, ok := s.(*ast.ExprStmt)
			if !ok {
				return true
			}
			call, ok := es.X.(*ast.CallExpr)
			if !ok || !isLogCall(pass, call) {
				return true
			}
			logged = true
		}
		if logged {
			report(pass, ifs, LP006, fmt.Sprintf("%s logs this error and carries on, so the caller is told it succeeded; return a RespError", fd.Name.Name))
		}
		return true
	})
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
