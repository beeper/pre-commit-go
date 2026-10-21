package rules

import (
	"go/ast"
	"go/constant"
	"go/types"
	"sort"
	"strings"
	"sync"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/types/typeutil"
)

const (
	pathMautrix  = "maunium.net/go/mautrix"
	pathBridgev2 = "maunium.net/go/mautrix/bridgev2"
	pathStatus   = "maunium.net/go/mautrix/bridgev2/status"
	pathEvent    = "maunium.net/go/mautrix/event"
	pathZerolog  = "github.com/rs/zerolog"
)

type Scope uint8

const (
	ScopeMatrixHandler Scope = 1 << iota
	ScopeLogin
	ScopeProvisioning
	ScopeLifecycle
)

var provisioningMethods = map[string]bool{
	"ResolveIdentifier":   true,
	"CreateGroup":         true,
	"CreateChatWithGhost": true,
	"SearchUsers":         true,
	"GetContactList":      true,
}

var lifecycleMethods = map[string]bool{
	"Connect":      true,
	"Disconnect":   true,
	"LogoutRemote": true,
}

// pkgInfo is shared by every analyzer that runs on the same package.
type pkgInfo struct {
	pass     *analysis.Pass
	bridgev2 *types.Package
	isBridge bool
	decls    map[*types.Func]*ast.FuncDecl
	scopes   map[*ast.FuncDecl]Scope
	parents  map[ast.Node]ast.Node
}

var pkgInfos sync.Map // *types.Package -> *pkgInfo

func infoFor(pass *analysis.Pass) *pkgInfo {
	if pi, ok := pkgInfos.Load(pass.Pkg); ok {
		return pi.(*pkgInfo)
	}
	pi := buildInfo(pass)
	actual, _ := pkgInfos.LoadOrStore(pass.Pkg, pi)
	return actual.(*pkgInfo)
}

func buildInfo(pass *analysis.Pass) *pkgInfo {
	pi := &pkgInfo{
		pass:    pass,
		decls:   map[*types.Func]*ast.FuncDecl{},
		scopes:  map[*ast.FuncDecl]Scope{},
		parents: map[ast.Node]ast.Node{},
	}
	for _, imp := range pass.Pkg.Imports() {
		if imp.Path() == pathBridgev2 {
			pi.bridgev2 = imp
		}
	}
	pi.isBridge = pi.bridgev2 != nil
	for _, f := range pass.Files {
		var stack []ast.Node
		ast.Inspect(f, func(n ast.Node) bool {
			if n == nil {
				stack = stack[:len(stack)-1]
				return true
			}
			if len(stack) > 0 {
				pi.parents[n] = stack[len(stack)-1]
			}
			stack = append(stack, n)
			return true
		})
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			if obj, ok := pass.TypesInfo.Defs[fd.Name].(*types.Func); ok {
				pi.decls[obj] = fd
			}
		}
	}
	if pi.isBridge {
		pi.classify()
	}
	return pi
}

func (pi *pkgInfo) lookupIface(name string) *types.Interface {
	if pi.bridgev2 == nil {
		return nil
	}
	obj := pi.bridgev2.Scope().Lookup(name)
	if obj == nil {
		return nil
	}
	iface, _ := obj.Type().Underlying().(*types.Interface)
	return iface
}

func implements(t types.Type, iface *types.Interface) bool {
	if iface == nil || t == nil {
		return false
	}
	if types.Implements(t, iface) {
		return true
	}
	if _, isPtr := t.(*types.Pointer); !isPtr {
		return types.Implements(types.NewPointer(t), iface)
	}
	return false
}

func (pi *pkgInfo) classify() {
	networkAPI := pi.lookupIface("NetworkAPI")
	networkConnector := pi.lookupIface("NetworkConnector")
	loginProcess := pi.lookupIface("LoginProcess")
	loginMethods := map[string]bool{}
	for _, name := range pi.bridgev2.Scope().Names() {
		if !strings.HasPrefix(name, "LoginProcess") {
			continue
		}
		if iface := pi.lookupIface(name); iface != nil {
			for i := 0; i < iface.NumMethods(); i++ {
				loginMethods[iface.Method(i).Name()] = true
			}
		}
	}
	for obj, fd := range pi.decls {
		sig := obj.Type().(*types.Signature)
		if sig.Recv() == nil {
			continue
		}
		recv := sig.Recv().Type()
		name := obj.Name()
		var scope Scope
		if implements(recv, networkAPI) {
			if strings.HasPrefix(name, "HandleMatrix") || strings.HasPrefix(name, "PreHandleMatrix") {
				scope |= ScopeMatrixHandler
			}
			if provisioningMethods[name] {
				scope |= ScopeProvisioning
			}
			if lifecycleMethods[name] {
				scope |= ScopeLifecycle
			}
		}
		if implements(recv, loginProcess) && loginMethods[name] {
			scope |= ScopeLogin
		}
		if implements(recv, networkConnector) && name == "CreateLogin" {
			scope |= ScopeLogin
		}
		if scope != 0 {
			pi.scopes[fd] = scope
		}
	}
}

func (pi *pkgInfo) declOf(call *ast.CallExpr) *ast.FuncDecl {
	fn, ok := typeutil.Callee(pi.pass.TypesInfo, call).(*types.Func)
	if !ok {
		return nil
	}
	return pi.decls[fn.Origin()]
}

// declsInOrder returns the package's function declarations in source order, for rules that report only
// the first of several matches.
func (pi *pkgInfo) declsInOrder() []*ast.FuncDecl {
	out := make([]*ast.FuncDecl, 0, len(pi.decls))
	for _, fd := range pi.decls {
		out = append(out, fd)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Pos() < out[j].Pos() })
	return out
}

func (pi *pkgInfo) funcsWithScope(s Scope) []*ast.FuncDecl {
	var out []*ast.FuncDecl
	for fd, scope := range pi.scopes {
		if scope&s != 0 {
			out = append(out, fd)
		}
	}
	return out
}

// enclosingFunc returns the innermost FuncDecl or FuncLit containing n.
func (pi *pkgInfo) enclosingFunc(n ast.Node) ast.Node {
	for p := pi.parents[n]; p != nil; p = pi.parents[p] {
		switch p.(type) {
		case *ast.FuncDecl, *ast.FuncLit:
			return p
		}
	}
	return nil
}

func isPkgFunc(fn types.Object, path string, names ...string) bool {
	if fn == nil || fn.Pkg() == nil || fn.Pkg().Path() != path {
		return false
	}
	if len(names) == 0 {
		return true
	}
	for _, name := range names {
		if fn.Name() == name {
			return true
		}
	}
	return false
}

func calleeObj(info *types.Info, call *ast.CallExpr) types.Object {
	return typeutil.Callee(info, call)
}

func isNamed(t types.Type, path, name string) bool {
	if t == nil {
		return false
	}
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	n, ok := types.Unalias(t).(*types.Named)
	if !ok || n.Obj().Pkg() == nil {
		return false
	}
	return n.Obj().Pkg().Path() == path && n.Obj().Name() == name
}

// httpStructFields are fields that net/http's Request and Response have and an API's own type with the
// same name usually doesn't.
var httpStructFields = map[string][]string{
	"Request":  {"Method", "URL", "Header", "Body", "GetBody"},
	"Response": {"Status", "StatusCode", "Header", "Body"},
}

// isHTTPStruct reports whether t, after dropping a pointer, is a struct called name with the fields of
// net/http's type of that name. The package isn't checked: net/http forks like fhttp declare their own
// Request and Response.
func isHTTPStruct(t types.Type, name string) bool {
	if t == nil {
		return false
	}
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := types.Unalias(t).(*types.Named)
	if !ok || named.Obj().Name() != name {
		return false
	}
	st, ok := named.Underlying().(*types.Struct)
	if !ok {
		return false
	}
	have := map[string]bool{}
	for i := 0; i < st.NumFields(); i++ {
		have[st.Field(i).Name()] = true
	}
	for _, field := range httpStructFields[name] {
		if !have[field] {
			return false
		}
	}
	return true
}

var errorType = types.Universe.Lookup("error").Type().Underlying().(*types.Interface)

func isErrorType(t types.Type) bool {
	return t != nil && types.Implements(t, errorType)
}

func isErrorInterface(t types.Type) bool {
	return t != nil && types.Identical(t, types.Universe.Lookup("error").Type())
}

func constString(info *types.Info, e ast.Expr) (string, bool) {
	tv, ok := info.Types[e]
	if !ok || tv.Value == nil {
		return "", false
	}
	if tv.Value.Kind() == constant.String {
		return constant.StringVal(tv.Value), true
	}
	return tv.Value.ExactString(), true
}

func constInt(info *types.Info, e ast.Expr) (int64, bool) {
	tv, ok := info.Types[e]
	if !ok || tv.Value == nil {
		return 0, false
	}
	v, exact := constant.Int64Val(constant.ToInt(tv.Value))
	return v, exact
}

func unparen(e ast.Expr) ast.Expr {
	for {
		p, ok := e.(*ast.ParenExpr)
		if !ok {
			return e
		}
		e = p.X
	}
}

func isTestFile(pass *analysis.Pass, n ast.Node) bool {
	return strings.HasSuffix(pass.Fset.Position(n.Pos()).Filename, "_test.go")
}

func funcBody(fn ast.Node) *ast.BlockStmt {
	switch f := fn.(type) {
	case *ast.FuncDecl:
		return f.Body
	case *ast.FuncLit:
		return f.Body
	}
	return nil
}

func funcType(info *types.Info, fn ast.Node) *types.Signature {
	switch f := fn.(type) {
	case *ast.FuncDecl:
		if obj, ok := info.Defs[f.Name]; ok && obj != nil {
			return obj.Type().(*types.Signature)
		}
	case *ast.FuncLit:
		if t, ok := info.Types[f].Type.(*types.Signature); ok {
			return t
		}
	}
	return nil
}

// inspectFunc walks a function body without descending into nested function literals.
func inspectFunc(body ast.Node, fn func(ast.Node) bool) {
	if body == nil {
		return
	}
	ast.Inspect(body, func(n ast.Node) bool {
		if _, ok := n.(*ast.FuncLit); ok && n != body {
			return false
		}
		return fn(n)
	})
}
