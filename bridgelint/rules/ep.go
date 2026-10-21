package rules

import (
	"go/ast"
	"go/token"
	"go/types"

	"golang.org/x/tools/go/analysis"
)

var EPAnalyzer = &analysis.Analyzer{
	Name: "ep",
	Doc:  "error plumbing rules (EP001-EP003): errors must be matched by type and carry typed statuses",
	Run:  runEP,
}

func runEP(pass *analysis.Pass) (any, error) {
	if err := ConfigError(pass); err != nil {
		return nil, err
	}
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
				if (x.Op == token.EQL || x.Op == token.NEQ) && (isErrText(x.X) && !isEmptyString(info, x.Y) || isErrText(x.Y) && !isEmptyString(info, x.X)) {
					report(pass, x, EP001, "error matched by comparing err.Error(); use errors.Is/errors.As or a typed code accessor")
				}
			case *ast.SwitchStmt:
				if x.Tag != nil && isErrText(x.Tag) {
					report(pass, x.Tag, EP001, "switch on err.Error(); use errors.Is/errors.As or a typed code accessor")
				}
			case *ast.CallExpr:
				obj := calleeObj(info, x)
				if isPkgFunc(obj, "strings", "EqualFold") && len(x.Args) > 0 && isErrText(x.Args[0]) {
					report(pass, x, EP001, "error matched with strings.EqualFold(err.Error(), ...); use errors.Is/errors.As or a typed code accessor")
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
	for _, arg := range call.Args[1:] {
		if isHTTPResponseStatus(pass.TypesInfo, arg) {
			report(pass, call, EP002, "HTTP status formatted into a plain error; return a typed error (e.g. *HTTPError{StatusCode}) so callers can tell 429 from 403 from 5xx")
			return
		}
	}
}

// isHTTPResponseStatus matches resp.StatusCode or resp.Status on an HTTP response (net/http or a fork).
func isHTTPResponseStatus(info *types.Info, e ast.Expr) bool {
	sel, ok := unparen(e).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "StatusCode" && sel.Sel.Name != "Status" {
		return false
	}
	selection, ok := info.Selections[sel]
	return ok && selection.Kind() == types.FieldVal && isHTTPStruct(selection.Recv(), "Response")
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
