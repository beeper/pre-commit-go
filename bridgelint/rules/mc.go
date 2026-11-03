package rules

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/cfg"
)

var MCAnalyzer = &analysis.Analyzer{
	Name: "mc",
	Doc:  "Matrix content rules (MC001-MC003): avatar hashes, media info and capabilities that clients depend on",
	Run:  runMC,
}

func runMC(pass *analysis.Pass) (any, error) {
	if err := ConfigError(pass); err != nil {
		return nil, err
	}
	for _, f := range pass.Files {
		if isTestFile(pass, f) {
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			var body *ast.BlockStmt
			switch fn := n.(type) {
			case *ast.FuncDecl:
				body = fn.Body
			case *ast.FuncLit:
				body = fn.Body
			}
			if body != nil {
				checkAvatarHash(pass, body)
				checkMediaInfo(pass, body)
			}
			return true
		})
	}
	checkGIFCapability(pass)
	return nil, nil
}

// compositeOf returns the composite literal e builds, looking through & and parentheses.
func compositeOf(e ast.Expr) *ast.CompositeLit {
	e = unparen(e)
	if u, ok := e.(*ast.UnaryExpr); ok && u.Op == token.AND {
		e = unparen(u.X)
	}
	lit, _ := e.(*ast.CompositeLit)
	return lit
}

func litField(lit *ast.CompositeLit, name string) (*ast.KeyValueExpr, bool) {
	for _, elt := range lit.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			if id, ok := kv.Key.(*ast.Ident); ok && id.Name == name {
				return kv, true
			}
		}
	}
	return nil, false
}

func isConstValue(info *types.Info, e ast.Expr, kind constant.Kind, match func(constant.Value) bool) bool {
	tv, ok := info.Types[e]
	return ok && tv.Value != nil && tv.Value.Kind() == kind && match(tv.Value)
}

func isStringConst(info *types.Info, e ast.Expr) bool {
	return isConstValue(info, e, constant.String, func(constant.Value) bool { return true })
}

// literalTargets maps each composite literal assigned or declared in body to the expression it's stored in.
func literalTargets(body ast.Node) map[*ast.CompositeLit]string {
	targets := map[*ast.CompositeLit]string{}
	ast.Inspect(body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			if len(x.Lhs) == len(x.Rhs) {
				for i, rhs := range x.Rhs {
					if lit := compositeOf(rhs); lit != nil {
						targets[lit] = types.ExprString(x.Lhs[i])
					}
				}
			}
		case *ast.ValueSpec:
			for i, name := range x.Names {
				if i < len(x.Values) {
					if lit := compositeOf(x.Values[i]); lit != nil {
						targets[lit] = name.Name
					}
				}
			}
		}
		return true
	})
	return targets
}

// checkAvatarHash implements MC001: bridgev2 compares the hash of a pre-uploaded avatar with the stored one
// and skips the update when they match and an MXC is already set, so an MXC without a hash makes every
// avatar change after the first a no-op.
func checkAvatarHash(pass *analysis.Pass, body *ast.BlockStmt) {
	info := pass.TypesInfo
	isAvatar := func(e ast.Expr) bool { return isNamed(info.TypeOf(e), pathBridgev2, "Avatar") }
	targets := literalTargets(body)
	hashAssigned := map[string]bool{}
	type built struct {
		lit     *ast.CompositeLit
		hasHash bool
	}
	litFor := map[string]built{}
	var mxcAssigns []*ast.SelectorExpr
	var noHash []*ast.KeyValueExpr
	ast.Inspect(body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.AssignStmt:
			for i, lhs := range x.Lhs {
				sel, ok := unparen(lhs).(*ast.SelectorExpr)
				if !ok || !isAvatar(sel.X) {
					continue
				}
				switch sel.Sel.Name {
				case "Hash":
					hashAssigned[types.ExprString(sel.X)] = true
				case "MXC":
					if len(x.Lhs) == len(x.Rhs) && isStringConst(info, x.Rhs[i]) {
						continue
					}
					mxcAssigns = append(mxcAssigns, sel)
				}
			}
		case *ast.CompositeLit:
			if !isAvatar(x) {
				return true
			}
			_, hasHash := litField(x, "Hash")
			if target, ok := targets[x]; ok {
				litFor[target] = built{x, hasHash}
			}
			mxc, hasMXC := litField(x, "MXC")
			// A constant MXC is a fixed avatar, which never needs a later update to get through.
			if !hasMXC || hasHash || isStringConst(info, mxc.Value) {
				return true
			}
			if rm, ok := litField(x, "Remove"); ok && isConstValue(info, rm.Value, constant.Bool, constant.BoolVal) {
				return true
			}
			noHash = append(noHash, mxc)
		}
		return true
	})
	const msg = "avatar has an MXC but no Hash; bridgev2 skips the update when the hash is unchanged, so later avatar changes never reach Matrix. Set Hash, e.g. sha256 of the remote avatar ID or URL"
	for _, kv := range noHash {
		var target string
		for lit, t := range targets {
			if v, ok := litField(lit, "MXC"); ok && v == kv {
				target = t
			}
		}
		if target != "" && hashAssigned[target] {
			continue
		}
		report(pass, kv, MC001, msg)
	}
	for _, sel := range mxcAssigns {
		target := types.ExprString(sel.X)
		b, ok := litFor[target]
		// Only avatars built in this function: one passed in or returned by a helper may already have a hash.
		if !ok || b.hasHash || hashAssigned[target] {
			continue
		}
		report(pass, sel, MC001, msg)
	}
}

var inlineMediaTypes = map[string]bool{"m.image": true, "m.video": true, "m.audio": true}

func isInlineMediaType(info *types.Info, e ast.Expr) bool {
	return isConstValue(info, e, constant.String, func(v constant.Value) bool { return inlineMediaTypes[constant.StringVal(v)] })
}

func isMessageContent(info *types.Info, e ast.Expr) bool {
	return isNamed(info.TypeOf(e), pathEvent, "MessageEventContent")
}

// checkMediaInfo implements MC003: image, video and audio content built in a function that never gets an
// Info on any path to the end of the function. Clients use info.mimetype to pick a renderer and name cached
// files, so a GIF without it shows as a still photo and iOS saves voice notes as unplayable .bin files.
func checkMediaInfo(pass *analysis.Pass, body *ast.BlockStmt) {
	info := pass.TypesInfo
	targets := literalTargets(body)
	// Locals that start as content literals without Info, keyed by variable.
	fresh := map[types.Object]*ast.CompositeLit{}
	for lit, target := range targets {
		if !isMessageContent(info, lit) {
			continue
		}
		if _, ok := litField(lit, "Info"); ok {
			continue
		}
		if obj := localVar(info, body, target, lit); obj != nil {
			fresh[obj] = lit
		}
	}
	type source struct {
		node ast.Node
		obj  types.Object // nil for a literal that isn't stored in a local
		lit  *ast.CompositeLit
	}
	var sources []source
	hasURL := map[types.Object]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.AssignStmt:
			for i, lhs := range x.Lhs {
				sel, ok := unparen(lhs).(*ast.SelectorExpr)
				if !ok || !isMessageContent(info, sel.X) {
					continue
				}
				id, ok := unparen(sel.X).(*ast.Ident)
				if !ok {
					continue
				}
				obj := info.ObjectOf(id)
				if _, ok := fresh[obj]; !ok {
					continue
				}
				switch sel.Sel.Name {
				case "URL", "File":
					hasURL[obj] = true
				case "MsgType":
					if len(x.Lhs) == len(x.Rhs) && isInlineMediaType(info, x.Rhs[i]) {
						sources = append(sources, source{node: x, obj: obj})
					}
				}
			}
		case *ast.CompositeLit:
			if !isMessageContent(info, x) {
				return true
			}
			mt, ok := litField(x, "MsgType")
			if !ok || !isInlineMediaType(info, mt.Value) {
				return true
			}
			if _, ok := litField(x, "Info"); ok {
				return true
			}
			_, url := litField(x, "URL")
			_, file := litField(x, "File")
			var obj types.Object
			if target, ok := targets[x]; ok {
				obj = localVar(info, body, target, x)
			}
			if obj != nil {
				if url || file {
					hasURL[obj] = true
				}
				sources = append(sources, source{node: x, obj: obj, lit: x})
			} else if url || file {
				sources = append(sources, source{node: x, lit: x})
			}
		}
		return true
	})
	if len(sources) == 0 {
		return
	}
	var g *cfg.CFG
	for _, src := range sources {
		if src.obj != nil && !hasURL[src.obj] {
			continue
		}
		if src.obj == nil && !anonymousContentDropsInfo(pass, body, src.lit) {
			continue
		}
		if g == nil {
			g = cfg.New(body, func(*ast.CallExpr) bool { return true })
		}
		if src.obj != nil && infoReachable(pass, g, src.node, src.obj) {
			continue
		}
		report(pass, src.node, MC003, "image, video or audio content without Info on any path; clients need info.mimetype (and w/h for images and video) to render it and name cached files")
	}
}

// localVar resolves target to a variable declared in body, or nil.
func localVar(info *types.Info, body *ast.BlockStmt, target string, lit *ast.CompositeLit) types.Object {
	var obj types.Object
	ast.Inspect(body, func(n ast.Node) bool {
		if obj != nil {
			return false
		}
		id, ok := n.(*ast.Ident)
		if ok && id.Name == target {
			if o, ok := info.Defs[id].(*types.Var); ok && o.Pos() >= body.Pos() && o.Pos() < body.End() {
				obj = o
			} else if o, ok := info.Uses[id].(*types.Var); ok && o.Pos() >= body.Pos() && o.Pos() < body.End() && id.Pos() < lit.Pos() {
				obj = o
			}
		}
		return true
	})
	return obj
}

// anonymousContentDropsInfo reports whether a content literal that isn't stored in a local can't get an
// Info later: it isn't a call argument and nothing in the function assigns any content's Info.
func anonymousContentDropsInfo(pass *analysis.Pass, body *ast.BlockStmt, lit *ast.CompositeLit) bool {
	info := pass.TypesInfo
	ok := true
	ast.Inspect(body, func(n ast.Node) bool {
		if !ok {
			return false
		}
		switch x := n.(type) {
		case *ast.CallExpr:
			for _, arg := range x.Args {
				if compositeOf(arg) == lit {
					ok = false
				}
			}
		case *ast.AssignStmt:
			for _, lhs := range x.Lhs {
				if sel, isSel := unparen(lhs).(*ast.SelectorExpr); isSel && sel.Sel.Name == "Info" && isMessageContent(info, sel.X) {
					ok = false
				}
			}
		}
		return ok
	})
	return ok
}

// infoReachable reports whether any statement reachable from src sets obj's Info, hands obj (or its
// Info) to a call, or replaces obj.
func infoReachable(pass *analysis.Pass, g *cfg.CFG, src ast.Node, obj types.Object) bool {
	info := pass.TypesInfo
	isObj := func(e ast.Expr) bool {
		e = unparen(e)
		if u, ok := e.(*ast.UnaryExpr); ok && u.Op == token.AND {
			e = unparen(u.X)
		}
		if sel, ok := e.(*ast.SelectorExpr); ok && sel.Sel.Name == "Info" {
			e = unparen(sel.X)
		}
		id, ok := e.(*ast.Ident)
		return ok && info.ObjectOf(id) == obj
	}
	sets := func(n ast.Node) bool {
		found := false
		ast.Inspect(n, func(m ast.Node) bool {
			if found {
				return false
			}
			switch x := m.(type) {
			case *ast.AssignStmt:
				for _, lhs := range x.Lhs {
					lhs = unparen(lhs)
					if id, ok := lhs.(*ast.Ident); ok && info.ObjectOf(id) == obj && !(x.Pos() <= src.Pos() && src.End() <= x.End()) {
						found = true
					}
					for {
						sel, ok := lhs.(*ast.SelectorExpr)
						if !ok {
							break
						}
						if sel.Sel.Name == "Info" && isObj(sel.X) {
							found = true
						}
						lhs = unparen(sel.X)
					}
				}
			case *ast.CallExpr:
				for _, arg := range x.Args {
					if isObj(arg) {
						found = true
					}
				}
			}
			return !found
		})
		return found
	}
	var start *cfg.Block
	startIdx := -1
	for _, b := range g.Blocks {
		for i, n := range b.Nodes {
			if n.Pos() <= src.Pos() && src.End() <= n.End() {
				start, startIdx = b, i
			}
		}
		if start != nil {
			break
		}
	}
	if start == nil {
		return true
	}
	for _, n := range start.Nodes[startIdx:] {
		if sets(n) {
			return true
		}
	}
	seen := map[*cfg.Block]bool{start: true}
	queue := append([]*cfg.Block(nil), start.Succs...)
	for len(queue) > 0 {
		b := queue[0]
		queue = queue[1:]
		if seen[b] {
			continue
		}
		seen[b] = true
		for _, n := range b.Nodes {
			if sets(n) {
				return true
			}
		}
		queue = append(queue, b.Succs...)
	}
	return false
}

// checkGIFCapability implements MC002: Beeper clients only enable their GIF picker when the room features
// list fi.mau.gif, so a bridge that accepts image/gif images but never declares it hides a working feature.
func checkGIFCapability(pass *analysis.Pass) {
	info := pass.TypesInfo
	declaresGIF := false
	var gifEntries []ast.Node
	for _, f := range pass.Files {
		if isTestFile(pass, f) {
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.Ident:
				if c, ok := info.Uses[x].(*types.Const); ok && c.Pkg() != nil && c.Pkg().Path() == pathEvent && c.Name() == "CapMsgGIF" {
					declaresGIF = true
				}
			case *ast.BasicLit:
				if isConstValue(info, x, constant.String, func(v constant.Value) bool { return constant.StringVal(v) == "fi.mau.gif" }) {
					declaresGIF = true
				}
			case *ast.CompositeLit:
				if !isNamed(info.TypeOf(x), pathEvent, "FileFeatureMap") {
					return true
				}
				for _, elt := range x.Elts {
					kv, ok := elt.(*ast.KeyValueExpr)
					if !ok || !isConstValue(info, kv.Key, constant.String, func(v constant.Value) bool { return constant.StringVal(v) == "m.image" }) {
						continue
					}
					if entry := gifMimeEntry(pass, kv.Value); entry != nil {
						gifEntries = append(gifEntries, entry)
					}
				}
			}
			return true
		})
	}
	if declaresGIF {
		return
	}
	for _, e := range gifEntries {
		report(pass, e, MC002, "image capabilities accept image/gif but no room features declare event.CapMsgGIF (fi.mau.gif), so clients keep their GIF picker disabled")
	}
}

// gifMimeEntry returns the "image/gif" entry of a supported image FileFeatures value, following
// MimeTypes to a package-level map variable.
func gifMimeEntry(pass *analysis.Pass, e ast.Expr) ast.Node {
	info := pass.TypesInfo
	lit := compositeOf(e)
	if lit == nil {
		return nil
	}
	mt, ok := litField(lit, "MimeTypes")
	if !ok {
		return nil
	}
	mimes := compositeOf(mt.Value)
	if mimes == nil {
		if id, ok := unparen(mt.Value).(*ast.Ident); ok {
			if v, ok := info.Uses[id].(*types.Var); ok && v.Parent() == pass.Pkg.Scope() {
				mimes = pkgVarLiteral(pass, v)
			}
		}
	}
	if mimes == nil {
		return nil
	}
	for _, elt := range mimes.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok || !isConstValue(info, kv.Key, constant.String, func(v constant.Value) bool { return constant.StringVal(v) == "image/gif" }) {
			continue
		}
		if isConstValue(info, kv.Value, constant.Int, func(v constant.Value) bool {
			n, exact := constant.Int64Val(v)
			return exact && n > 0
		}) {
			return kv
		}
	}
	return nil
}

func pkgVarLiteral(pass *analysis.Pass, v *types.Var) *ast.CompositeLit {
	for _, f := range pass.Files {
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, spec := range gd.Specs {
				vs := spec.(*ast.ValueSpec)
				for i, name := range vs.Names {
					if pass.TypesInfo.Defs[name] == v && i < len(vs.Values) {
						return compositeOf(vs.Values[i])
					}
				}
			}
		}
	}
	return nil
}
