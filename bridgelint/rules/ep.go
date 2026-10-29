package rules

import (
	"go/ast"
	"go/token"
	"go/types"

	"golang.org/x/tools/go/analysis"
)

var EPAnalyzer = &analysis.Analyzer{
	Name: "ep",
	Doc:  "error plumbing rules (EP001-EP004): errors must be matched by type, carry typed statuses and not vanish",
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
			case *ast.FuncDecl, *ast.FuncLit:
				if sig := funcType(info, x); sig != nil && sig.Results().Len() == 0 {
					checkDroppedDecode(pass, funcBody(x))
				}
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
				if !pi.isBridge && pass.Pkg.Name() != "main" && isPkgFunc(obj, "fmt", "Errorf") {
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

func isDecodeCall(info *types.Info, e ast.Expr) bool {
	call, ok := unparen(e).(*ast.CallExpr)
	if !ok {
		return false
	}
	fn, ok := calleeObj(info, call).(*types.Func)
	if !ok {
		return false
	}
	if sig, _ := fn.Type().(*types.Signature); sig != nil && sig.Recv() != nil {
		return fn.Name() == "Decode" && isNamed(sig.Recv().Type(), "encoding/json", "Decoder")
	}
	return isPkgFunc(fn, "encoding/json", "Unmarshal") || isPkgFunc(fn, "google.golang.org/protobuf/proto", "Unmarshal")
}

// checkDroppedDecode implements EP004: in a function that can't return the error, a failed decode that
// only returns leaves no trace, so a payload shape the code didn't expect looks like a message that never
// arrived. Only bare returns are flagged: continue usually skips entries of other shapes on purpose.
func checkDroppedDecode(pass *analysis.Pass, body *ast.BlockStmt) {
	info := pass.TypesInfo
	inspectFunc(body, func(n ast.Node) bool {
		ifs, ok := n.(*ast.IfStmt)
		if !ok || ifs.Else != nil || len(ifs.Body.List) != 1 {
			return true
		}
		if ret, ok := ifs.Body.List[0].(*ast.ReturnStmt); !ok || len(ret.Results) != 0 {
			return true
		}
		var errVar types.Object
		if as, ok := ifs.Init.(*ast.AssignStmt); ok && len(as.Lhs) == 1 && len(as.Rhs) == 1 && isDecodeCall(info, as.Rhs[0]) {
			if id, ok := as.Lhs[0].(*ast.Ident); ok {
				errVar = info.ObjectOf(id)
			}
		}
		var decodeCheck ast.Expr
		var visit func(e ast.Expr)
		visit = func(e ast.Expr) {
			be, ok := unparen(e).(*ast.BinaryExpr)
			if !ok {
				return
			}
			switch be.Op {
			case token.LOR:
				visit(be.X)
				visit(be.Y)
			case token.NEQ:
				if !isNilIdent(info, be.Y) {
					return
				}
				if isDecodeCall(info, be.X) {
					decodeCheck = be
				} else if id, ok := unparen(be.X).(*ast.Ident); ok && errVar != nil && info.ObjectOf(id) == errVar {
					decodeCheck = be
				}
			}
		}
		visit(ifs.Cond)
		if decodeCheck != nil {
			report(pass, decodeCheck, EP004, "decode error dropped with a bare return; log it or pass it to an error handler, or a payload the code didn't expect vanishes without a trace")
		}
		return true
	})
}

func isNilIdent(info *types.Info, e ast.Expr) bool {
	id, ok := unparen(e).(*ast.Ident)
	if !ok {
		return false
	}
	_, isNil := info.Uses[id].(*types.Nil)
	return isNil
}
