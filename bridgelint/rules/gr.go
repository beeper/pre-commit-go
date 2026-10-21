package rules

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"regexp"
	"strings"

	"golang.org/x/tools/go/analysis"
)

var GRAnalyzer = &analysis.Analyzer{
	Name: "gr",
	Doc:  "general reliability rules (GR001-GR013) found repeatedly in bridge audits",
	Run:  runGR,
}

var (
	cursorFieldRegex = regexp.MustCompile(`(?i:cursor|checkpoint|sync_?token)|(^|_)seq|Seq|^[Pp]ts$|Pts$`)
	stopNameRegex    = regexp.MustCompile(`(?i)disconnect|stop|close|cancel|shutdown`)
)

func runGR(pass *analysis.Pass) (any, error) {
	if err := ConfigError(pass); err != nil {
		return nil, err
	}
	pi := infoFor(pass)
	for _, f := range pass.Files {
		if isTestFile(pass, f) {
			continue
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			checkBodyClose(pass, fd)
			checkRetryBody(pass, fd)
			if pi.isBridge {
				checkCursorBeforeHandled(pass, fd)
			}
		}
		checkHTTPWithoutCtx(pass, f)
		checkExits(pass, pi, f)
	}
	if pi.isBridge {
		checkSharedState(pass, pi)
		checkCapabilitiesID(pass, pi)
		if FrameworkHas(FeatureDisconnectAfterLogout) {
			// Newer bridgev2 disconnects after LogoutRemote itself.
		} else {
			checkLogoutRemote(pass, pi)
		}
	}
	return nil, nil
}

func isHTTPResponse(t types.Type) bool {
	return isNamed(t, "net/http", "Response")
}

// checkBodyClose implements GR001.
func checkBodyClose(pass *analysis.Pass, fd *ast.FuncDecl) {
	info := pass.TypesInfo
	type respVar struct {
		obj  types.Object
		node ast.Node
	}
	var vars []respVar
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Rhs) != 1 {
			return true
		}
		call, ok := unparen(as.Rhs[0]).(*ast.CallExpr)
		if !ok {
			return true
		}
		// Only calls that hand the caller an open body: wrappers may close it before returning.
		f, ok := calleeObj(info, call).(*types.Func)
		if !ok || !isHTTPRoundTrip(f) && !isNetworkPrimitive(f) {
			return true
		}
		for _, lhs := range as.Lhs {
			id, ok := lhs.(*ast.Ident)
			if !ok || id.Name == "_" {
				continue
			}
			if v := info.ObjectOf(id); v != nil && isHTTPResponse(v.Type()) {
				vars = append(vars, respVar{v, as})
			}
		}
		return true
	})
	for _, rv := range vars {
		closed, escapes := false, false
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				if inner, ok := x.X.(*ast.SelectorExpr); ok && x.Sel.Name == "Close" && inner.Sel.Name == "Body" {
					if id, ok := inner.X.(*ast.Ident); ok && info.ObjectOf(id) == rv.obj {
						closed = true
					}
				}
			case *ast.CallExpr:
				for _, arg := range x.Args {
					if usesObjDirectly(info, arg, rv.obj) {
						escapes = true
					}
				}
			case *ast.ReturnStmt:
				for _, r := range x.Results {
					if usesObjDirectly(info, r, rv.obj) {
						escapes = true
					}
				}
			case *ast.AssignStmt:
				if x != rv.node {
					for _, r := range x.Rhs {
						if usesObjDirectly(info, r, rv.obj) {
							escapes = true
						}
					}
				}
			case *ast.CompositeLit:
				for _, elt := range x.Elts {
					if kv, ok := elt.(*ast.KeyValueExpr); ok {
						elt = kv.Value
					}
					if usesObjDirectly(info, elt, rv.obj) {
						escapes = true
					}
				}
			}
			return true
		})
		if !closed && !escapes {
			report(pass, rv.node, GR001, fmt.Sprintf("%s.Body is never closed; add defer %s.Body.Close() after the error check", rv.obj.Name(), rv.obj.Name()))
		}
	}
}

func usesObjDirectly(info *types.Info, e ast.Expr, obj types.Object) bool {
	e = unparen(e)
	if u, ok := e.(*ast.UnaryExpr); ok {
		e = u.X
	}
	if sel, ok := e.(*ast.SelectorExpr); ok && sel.Sel.Name == "Body" {
		e = sel.X
	}
	id, ok := e.(*ast.Ident)
	return ok && info.ObjectOf(id) == obj
}

// checkHTTPWithoutCtx implements GR002.
func checkHTTPWithoutCtx(pass *analysis.Pass, f *ast.File) {
	info := pass.TypesInfo
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			obj := calleeObj(info, x)
			if isPkgFunc(obj, "net/http", "Get", "Post", "Head", "PostForm") {
				if _, isFunc := obj.(*types.Func); isFunc && recvType(obj) == nil {
					report(pass, x, GR002, fmt.Sprintf("http.%s uses DefaultClient with no context or timeout; build the request with http.NewRequestWithContext and a client that has a Timeout", obj.Name()))
				}
			}
			if isPkgFunc(obj, "net/http", "NewRequest") {
				report(pass, x, GR002, "http.NewRequest has no context, so the request can't be cancelled; use http.NewRequestWithContext")
			}
		case *ast.SelectorExpr:
			if obj := info.Uses[x.Sel]; isPkgFunc(obj, "net/http", "DefaultClient") {
				report(pass, x, GR002, "http.DefaultClient has no timeout; use a client with Timeout set")
			}
		}
		return true
	})
}

// checkRetryBody implements GR003.
func checkRetryBody(pass *analysis.Pass, fd *ast.FuncDecl) {
	info := pass.TypesInfo
	bodyReqs := map[types.Object]ast.Node{}
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Rhs) != 1 || len(as.Lhs) < 1 {
			return true
		}
		call, ok := unparen(as.Rhs[0]).(*ast.CallExpr)
		if !ok {
			return true
		}
		obj := calleeObj(info, call)
		bodyIdx := -1
		if isPkgFunc(obj, "net/http", "NewRequest") {
			bodyIdx = 2
		} else if isPkgFunc(obj, "net/http", "NewRequestWithContext") {
			bodyIdx = 3
		}
		if bodyIdx < 0 || bodyIdx >= len(call.Args) {
			return true
		}
		body := unparen(call.Args[bodyIdx])
		if id, ok := body.(*ast.Ident); ok && id.Name == "nil" {
			return true
		}
		if sel, ok := body.(*ast.SelectorExpr); ok && sel.Sel.Name == "NoBody" {
			return true
		}
		if id, ok := as.Lhs[0].(*ast.Ident); ok {
			if v := info.ObjectOf(id); v != nil {
				bodyReqs[v] = as
			}
		}
		return true
	})
	if len(bodyReqs) == 0 {
		return
	}
	if setsGetBody(info, fd) {
		return
	}
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		var loopBody *ast.BlockStmt
		switch x := n.(type) {
		case *ast.ForStmt:
			loopBody = x.Body
		case *ast.RangeStmt:
			loopBody = x.Body
		default:
			return true
		}
		ast.Inspect(loopBody, func(m ast.Node) bool {
			call, ok := m.(*ast.CallExpr)
			if !ok {
				return true
			}
			obj := calleeObj(info, call)
			if obj == nil || obj.Name() != "Do" || len(call.Args) != 1 {
				return true
			}
			id, ok := unparen(call.Args[0]).(*ast.Ident)
			if !ok {
				return true
			}
			v := info.ObjectOf(id)
			def, ok := bodyReqs[v]
			if !ok || containsNode(loopBody, def) {
				return true
			}
			report(pass, call, GR003, fmt.Sprintf("%s is built once with a body and re-sent in a loop; the body is empty on retries. Rebuild the request per attempt or set GetBody", id.Name))
			return true
		})
		return false
	})
}

// setsGetBody reports whether fd sets Request.GetBody, which lets the body be replayed on a retry.
func setsGetBody(info *types.Info, fd *ast.FuncDecl) bool {
	found := false
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			if sel, ok := info.Selections[x]; ok && x.Sel.Name == "GetBody" && sel.Kind() == types.FieldVal && isHTTPStruct(sel.Recv(), "Request") {
				found = true
			}
		case *ast.CompositeLit:
			if !isHTTPStruct(info.TypeOf(x), "Request") {
				return true
			}
			for _, elt := range x.Elts {
				if kv, ok := elt.(*ast.KeyValueExpr); ok {
					if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "GetBody" {
						found = true
					}
				}
			}
		}
		return !found
	})
	return found
}

// checkExits implements GR004.
func checkExits(pass *analysis.Pass, pi *pkgInfo, f *ast.File) {
	if pass.Pkg.Name() == "main" {
		return
	}
	info := pass.TypesInfo
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Body == nil || (fd.Recv == nil && fd.Name.Name == "init") || strings.HasPrefix(fd.Name.Name, "Must") || strings.HasPrefix(fd.Name.Name, "must") {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			obj := calleeObj(info, call)
			switch {
			case isPkgFunc(obj, "os", "Exit"):
				report(pass, call, GR004, "os.Exit in connector or library code kills every login on the process; return an error instead")
			// Panic variants aren't reported: they're a logged panic, and plain panics aren't either.
			case isPkgFunc(obj, "log", "Fatal", "Fatalf", "Fatalln"):
				report(pass, call, GR004, fmt.Sprintf("log.%s in connector or library code kills the process; return an error instead", obj.Name()))
			case isPkgFunc(obj, pathZerolog, "Fatal"):
				report(pass, call, GR004, "zerolog Fatal() exits the process; log at Error and return an error instead")
			}
			return true
		})
	}
}

// checkCursorBeforeHandled implements GR008.
func checkCursorBeforeHandled(pass *analysis.Pass, fd *ast.FuncDecl) {
	var queueLoopEnd token.Pos
	inspectFunc(fd.Body, func(n ast.Node) bool {
		var body *ast.BlockStmt
		switch x := n.(type) {
		case *ast.ForStmt:
			body = x.Body
		case *ast.RangeStmt:
			body = x.Body
		default:
			return true
		}
		found := false
		ast.Inspect(body, func(m ast.Node) bool {
			if call, ok := m.(*ast.CallExpr); ok && isPkgFunc(calleeObj(pass.TypesInfo, call), pathBridgev2, "QueueRemoteEvent") {
				found = true
			}
			return !found
		})
		if found && n.End() > queueLoopEnd {
			queueLoopEnd = n.End()
		}
		return true
	})
	if queueLoopEnd == token.NoPos {
		return
	}
	inspectFunc(fd.Body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || as.Pos() < queueLoopEnd {
			return true
		}
		for _, lhs := range as.Lhs {
			if sel, ok := lhs.(*ast.SelectorExpr); ok && cursorFieldRegex.MatchString(sel.Sel.Name) {
				report(pass, as, GR008, fmt.Sprintf("%s is saved after queueing remote events but before they're handled; a crash loses them. Move the cursor from the event's completion, or disable the portal event buffer", sel.Sel.Name))
				return false
			}
		}
		return true
	})
}

// checkSharedState implements GR009.
func checkSharedState(pass *analysis.Pass, pi *pkgInfo) {
	info := pass.TypesInfo
	reported := map[types.Object]bool{}
	for _, fd := range pi.declsInOrder() {
		if fd.Recv == nil && fd.Name.Name == "init" {
			continue
		}
		if isTestFile(pass, fd) {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			var targets []ast.Expr
			switch x := n.(type) {
			case *ast.AssignStmt:
				if x.Tok == token.DEFINE {
					return true
				}
				targets = x.Lhs
			case *ast.IncDecStmt:
				targets = []ast.Expr{x.X}
			case *ast.CallExpr:
				if obj := calleeObj(info, x); (obj == types.Universe.Lookup("delete") || obj == types.Universe.Lookup("clear")) && len(x.Args) > 0 {
					targets = []ast.Expr{x.Args[0]}
				}
			}
			for _, t := range targets {
				v := rootPkgVar(info, pass.Pkg, t)
				if v == nil || reported[v] || !isMutableShared(v.Type()) {
					continue
				}
				reported[v] = true
				report(pass, t, GR009, fmt.Sprintf("package-level %s is written at runtime and shared by every login on the process; move it onto the client or connector", v.Name()))
			}
			return true
		})
	}
}

func rootPkgVar(info *types.Info, pkg *types.Package, e ast.Expr) *types.Var {
	for {
		switch x := unparen(e).(type) {
		case *ast.Ident:
			v, ok := info.ObjectOf(x).(*types.Var)
			if ok && v.Pkg() == pkg && v.Parent() == pkg.Scope() {
				return v
			}
			return nil
		case *ast.IndexExpr:
			e = x.X
		case *ast.SelectorExpr:
			if _, ok := info.Selections[x]; !ok {
				return nil
			}
			e = x.X
		case *ast.StarExpr:
			e = x.X
		default:
			return nil
		}
	}
}

// isMutableShared reports whether t is a map or slice. sync.Map, atomic.Value and the rest synchronise
// themselves and are structs, so the underlying type is all this has to look at.
func isMutableShared(t types.Type) bool {
	switch t.Underlying().(type) {
	case *types.Map, *types.Slice:
		return true
	}
	return false
}

// checkCapabilitiesID implements GR011.
func checkCapabilitiesID(pass *analysis.Pass, pi *pkgInfo) {
	info := pass.TypesInfo
	for obj, fd := range pi.decls {
		if obj.Name() != "GetCapabilities" || recvType(obj) == nil {
			continue
		}
		isFeatures := func(e ast.Expr) bool { return isNamed(info.TypeOf(e), pathEvent, "RoomFeatures") }
		idSet := false
		var mutation ast.Node
		var mutatedField string
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for _, lhs := range as.Lhs {
				sel, ok := lhs.(*ast.SelectorExpr)
				if !ok || !isFeatures(sel.X) {
					continue
				}
				if sel.Sel.Name == "ID" {
					idSet = true
				} else if mutation == nil {
					mutation, mutatedField = as, sel.Sel.Name
				}
			}
			return true
		})
		if mutation != nil && !idSet {
			report(pass, mutation, GR011, fmt.Sprintf("GetCapabilities changes %s but keeps the same RoomFeatures.ID; clients cache features by ID, so give each variant its own ID", mutatedField))
		}
	}
}

// checkLogoutRemote implements GR013.
func checkLogoutRemote(pass *analysis.Pass, pi *pkgInfo) {
	for fd, scope := range pi.scopes {
		if scope&ScopeLifecycle == 0 || fd.Name.Name != "LogoutRemote" {
			continue
		}
		if !callsMatching(pass, pi, fd.Body, stopNameRegex, 1) {
			report(pass, fd.Name, GR013, "LogoutRemote doesn't disconnect the client, so its loops keep running after logout")
		}
	}
}

func callsMatching(pass *analysis.Pass, pi *pkgInfo, body ast.Node, re *regexp.Regexp, depth int) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found {
			return !found
		}
		var name string
		switch fun := unparen(call.Fun).(type) {
		case *ast.Ident:
			name = fun.Name
		case *ast.SelectorExpr:
			name = fun.Sel.Name
		}
		if re.MatchString(name) {
			found = true
			return false
		}
		if depth > 0 {
			if fd := pi.declOf(call); fd != nil && callsMatching(pass, pi, fd.Body, re, depth-1) {
				found = true
			}
		}
		return !found
	})
	return found
}
