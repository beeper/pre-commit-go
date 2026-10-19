package rules

import (
	"go/ast"
	"go/constant"
	"go/types"
	"regexp"
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
	pass      *analysis.Pass
	bridgev2  *types.Package
	isBridge  bool
	decls     map[*types.Func]*ast.FuncDecl
	scopes    map[*ast.FuncDecl]Scope
	goTargets map[*ast.FuncDecl]bool
	goLits    []*ast.FuncLit
	parents   map[ast.Node]ast.Node
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
		pass:      pass,
		decls:     map[*types.Func]*ast.FuncDecl{},
		scopes:    map[*ast.FuncDecl]Scope{},
		goTargets: map[*ast.FuncDecl]bool{},
		parents:   map[ast.Node]ast.Node{},
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
	for _, f := range pass.Files {
		ast.Inspect(f, func(n ast.Node) bool {
			gs, ok := n.(*ast.GoStmt)
			if !ok {
				return true
			}
			if lit, ok := gs.Call.Fun.(*ast.FuncLit); ok {
				pi.goLits = append(pi.goLits, lit)
				ast.Inspect(lit.Body, func(n ast.Node) bool {
					if call, ok := n.(*ast.CallExpr); ok {
						if fd := pi.declOf(call); fd != nil {
							pi.goTargets[fd] = true
						}
					}
					return true
				})
			} else if fd := pi.declOf(gs.Call); fd != nil {
				pi.goTargets[fd] = true
			}
			return true
		})
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

func (pi *pkgInfo) enclosingDecl(n ast.Node) *ast.FuncDecl {
	for p := pi.parents[n]; p != nil; p = pi.parents[p] {
		if fd, ok := p.(*ast.FuncDecl); ok {
			return fd
		}
	}
	return nil
}

// isNetworkPackage reports whether errors from this import path count as raw network/library errors.
func isNetworkPackage(cfg *Config, self *types.Package, path string) bool {
	if len(cfg.NetworkPackages) > 0 {
		for _, prefix := range cfg.NetworkPackages {
			prefix = strings.TrimSuffix(prefix, "/...")
			if path == prefix || strings.HasPrefix(path, prefix+"/") {
				return true
			}
		}
		return false
	}
	if path == "net/http" || path == "net" {
		return true
	}
	if path == self.Path() {
		return false
	}
	first, _, _ := strings.Cut(path, "/")
	if !strings.Contains(first, ".") {
		return false
	}
	if path == pathMautrix || strings.HasPrefix(path, pathMautrix+"/") || strings.HasPrefix(path, "go.mau.fi/util") {
		return false
	}
	if strings.HasPrefix(path, "github.com/rs/zerolog") || isDatabasePackage(path) {
		return false
	}
	if first == "golang.org" {
		return strings.HasPrefix(path, "golang.org/x/net")
	}
	return true
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
	s := tv.Value.ExactString()
	if len(s) >= 2 && s[0] == '"' {
		return strings.Trim(s, `"`), true
	}
	return s, true
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

var dbPackageRegex = regexp.MustCompile(`(?i)(^|/)(\w*db|database|store|storage|\w*ids?)(/|$)`)

// isDatabasePackage treats a bridge's own database and ID-parsing packages as internal rather than
// network: a failed DB query or ID parse is an internal error, not something to classify for the user.
func isDatabasePackage(path string) bool {
	return dbPackageRegex.MatchString(path)
}
