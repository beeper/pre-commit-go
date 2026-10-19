package rules

import (
	"fmt"
	"go/ast"
	"go/token"
	"regexp"

	"golang.org/x/tools/go/analysis"
)

var EPAnalyzer = &analysis.Analyzer{
	Name: "ep",
	Doc:  "error plumbing rules (EP001-EP003): errors must be matched by type and carry typed statuses",
	Run:  runEP,
}

var httpStatusFormatRegex = regexp.MustCompile(`(?i)\b(http|status|code)\b[^%]{0,20}%d`)

func runEP(pass *analysis.Pass) (any, error) {
	pi := infoFor(pass)
	info := pass.TypesInfo
	isErrText := func(e ast.Expr) bool {
		call, ok := unparen(e).(*ast.CallExpr)
		if !ok || len(call.Args) != 0 {
			return false
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		return ok && sel.Sel.Name == "Error" && isErrorType(info.TypeOf(sel.X))
	}
	for _, f := range pass.Files {
		if isTestFile(pass, f) {
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.BinaryExpr:
				if (x.Op == token.EQL || x.Op == token.NEQ) && (isErrText(x.X) || isErrText(x.Y)) {
					report(pass, x, EP001, "error matched by comparing err.Error(); use errors.Is/errors.As or a typed code accessor")
				}
			case *ast.SwitchStmt:
				if x.Tag != nil && isErrText(x.Tag) {
					report(pass, x.Tag, EP001, "switch on err.Error(); use errors.Is/errors.As or a typed code accessor")
				}
			case *ast.CallExpr:
				obj := calleeObj(info, x)
				if isPkgFunc(obj, "strings", "Contains", "HasPrefix", "HasSuffix", "EqualFold", "Index") && len(x.Args) > 0 && isErrText(x.Args[0]) {
					report(pass, x, EP001, fmt.Sprintf("error matched with strings.%s(err.Error(), ...); use errors.Is/errors.As or a typed code accessor", obj.Name()))
				}
				if !pi.isBridge && isPkgFunc(obj, "fmt", "Errorf") {
					checkUntypedHTTPError(pass, x)
				}
			case *ast.KeyValueExpr:
				if key, ok := x.Key.(*ast.Ident); ok && key.Name == "Message" && containsErrorsJoin(pass, x.Value) {
					report(pass, x.Value, EP003, "errors.Join text used as a user-facing message")
				}
			}
			return true
		})
	}
	return nil, nil
}

func checkUntypedHTTPError(pass *analysis.Pass, call *ast.CallExpr) {
	format, ok := stringArg(pass.TypesInfo, call, 0)
	if !ok {
		return
	}
	hasStatusArg := false
	for _, arg := range call.Args[1:] {
		if sel, ok := unparen(arg).(*ast.SelectorExpr); ok && (sel.Sel.Name == "StatusCode" || sel.Sel.Name == "Status") {
			hasStatusArg = true
		}
	}
	if hasStatusArg || httpStatusFormatRegex.MatchString(format) {
		report(pass, call, EP002, "HTTP status formatted into a plain error; return a typed error (e.g. *HTTPError{StatusCode}) so callers can tell 429 from 403 from 5xx")
	}
}

func containsErrorsJoin(pass *analysis.Pass, e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && isPkgFunc(calleeObj(pass.TypesInfo, call), "errors", "Join") {
			found = true
		}
		return !found
	})
	return found
}
