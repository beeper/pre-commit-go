package rules

import (
	"go/ast"
	"go/token"
	"go/types"
	"reflect"
	"sort"
	"strings"
	"sync"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/types/typeutil"
)

// NetAnalyzer finds the functions that can reach the network. It follows calls through every package
// the bridge depends on, from source, down to a small set of standard library primitives (HTTP round
// trips, dials and connection reads/writes), and passes what it finds to importers as facts. The error
// rules use it to tell a library error that came from the network apart from an internal one.
var NetAnalyzer = &analysis.Analyzer{
	Name:       "bridgelintnet",
	Doc:        "finds functions that can reach the network (used by the error rules; reports nothing)",
	Run:        runNet,
	ResultType: reflect.TypeOf((*netReach)(nil)),
	FactTypes:  []analysis.Fact{new(netFuncFact), new(netPkgFact)},
}

// maxIfaceRefs caps the unresolved interface calls carried in one fact.
const maxIfaceRefs = 16

// ifaceRef is a call through a method of a named interface.
type ifaceRef struct {
	Pkg, Type, Method string
	Ctx               bool // the call passes a context
}

// netFuncFact records that a function reaches the network, or calls interface methods that no
// implementation visible from its package resolved. Importers that can see more implementations resolve
// them again.
type netFuncFact struct {
	Network bool
	Ifaces  []ifaceRef
	// Hidden is set when the function makes calls that can't be followed: context-taking calls through
	// func values or interfaces nothing visible implements, or reads and writes on a buffered connection
	// kept in a struct field. Protocol libraries reach their connection that way (a websocket writing
	// through a bufio.Writer, an MTProto client invoking through a chain of func values).
	Hidden bool
}

func (*netFuncFact) AFact() {}

func (f *netFuncFact) String() string {
	if f.Network {
		return "network"
	}
	var parts []string
	if f.Hidden {
		parts = append(parts, "hidden")
	}
	for _, r := range f.Ifaces {
		parts = append(parts, "iface="+r.Pkg+"."+r.Type+"."+r.Method)
	}
	return strings.Join(parts, ",")
}

// netPkgFact records that a package, or a package it imports, has functions that reach the network: it's
// a network library, and its exported error values are network library errors.
type netPkgFact struct{ Network bool }

func (*netPkgFact) AFact()         {}
func (*netPkgFact) String() string { return "network" }

type netReach struct {
	pass    *analysis.Pass
	cfg     *Config
	local   map[*types.Func]bool
	pkgs    map[string]*types.Package
	impls   []*types.Func // methods of concrete types, here or in dependencies, that reach the network
	ifaces  map[ifaceRef]bool
	network bool // the package is a network library
	hidden  map[*types.Func]bool
	// unresolved holds the interface calls each local function that doesn't reach the network makes,
	// directly or through local callees, that no visible implementation resolved.
	unresolved map[*types.Func]map[ifaceRef]bool
	implCache  map[ifaceRef]bool
	// mu guards the caches: the error analyzers share the result and run concurrently.
	mu sync.Mutex
}

func runNet(pass *analysis.Pass) (any, error) {
	r := &netReach{
		pass:   pass,
		cfg:    ConfigFor(pass),
		local:  map[*types.Func]bool{},
		pkgs:   map[string]*types.Package{},
		ifaces: map[ifaceRef]bool{},
		hidden: map[*types.Func]bool{},

		implCache: map[ifaceRef]bool{},
	}
	if pass.TypesInfo == nil || notFollowed(pass.Pkg.Path()) {
		return r, nil
	}
	var walk func(p *types.Package)
	walk = func(p *types.Package) {
		if r.pkgs[p.Path()] != nil {
			return
		}
		r.pkgs[p.Path()] = p
		for _, imp := range p.Imports() {
			walk(imp)
		}
	}
	walk(pass.Pkg)
	for _, of := range pass.AllObjectFacts() {
		f, ok := of.Object.(*types.Func)
		if fact, isNet := of.Fact.(*netFuncFact); ok && isNet && fact.Network && isConcreteMethod(f) {
			r.impls = append(r.impls, f)
		}
	}

	pi := infoFor(pass)
	type node struct {
		obj     *types.Func
		callees []*types.Func
		refs    map[ifaceRef]bool
	}
	nodes := map[*types.Func]*node{}
	callers := map[*types.Func][]*types.Func{}
	for obj, fd := range pi.decls {
		n := &node{obj: obj, refs: map[ifaceRef]bool{}}
		nodes[obj] = n
		// Function literals count as part of the function only when they're called right away or passed
		// to a call as a callback; one that's stored or returned runs later, if at all.
		calledLits := map[*ast.FuncLit]bool{}
		received := receivedChans(pass.TypesInfo, fd.Body)
		ast.Inspect(fd.Body, func(an ast.Node) bool {
			switch an := an.(type) {
			case *ast.GoStmt:
				// Errors from goroutines a function starts can't be returned by it, unless the goroutine
				// sends them to a channel the function waits on.
				if lit := asFuncLit(an.Call.Fun); lit != nil && sendsTo(pass.TypesInfo, lit.Body, received) {
					return true
				}
				return false
			case *ast.FuncLit:
				return calledLits[an]
			}
			call, ok := an.(*ast.CallExpr)
			if !ok {
				return true
			}
			if lit, ok := unparen(call.Fun).(*ast.FuncLit); ok {
				calledLits[lit] = true
			}
			for _, arg := range call.Args {
				if lit, ok := unparen(arg).(*ast.FuncLit); ok {
					calledLits[lit] = true
				}
			}
			callee := typeutil.Callee(pass.TypesInfo, call)
			f, ok := callee.(*types.Func)
			if !ok {
				if _, builtin := callee.(*types.Builtin); !builtin && !pass.TypesInfo.Types[call.Fun].IsType() && asFuncLit(call.Fun) == nil && passesContext(pass.TypesInfo, call) {
					r.hidden[obj] = true
				}
				return true
			}
			f = f.Origin()
			if isBufferedConnIO(f, call) {
				r.hidden[obj] = true
			}
			if pi.decls[f] != nil {
				n.callees = append(n.callees, f)
				callers[f] = append(callers[f], obj)
				return true
			}
			if isNetworkPrimitive(f) {
				r.local[obj] = true
				return true
			}
			if ref, ok := r.ifaceRefOf(f); ok {
				ref.Ctx = passesContext(pass.TypesInfo, call)
				n.refs[ref] = true
				return true
			}
			network, refs, hidden := r.imported(f)
			if network {
				r.local[obj] = true
			}
			if hidden {
				r.hidden[obj] = true
			}
			for _, ref := range refs {
				n.refs[ref] = true
			}
			return true
		})
	}

	// Mark callers of network functions, then resolve interface calls against the methods found so far,
	// until nothing changes.
	var work []*types.Func
	for obj := range r.local {
		work = append(work, obj)
	}
	propagate := func() {
		for len(work) > 0 {
			obj := work[len(work)-1]
			work = work[:len(work)-1]
			for _, caller := range callers[obj] {
				if !r.local[caller] {
					r.local[caller] = true
					work = append(work, caller)
				}
			}
		}
	}
	for {
		propagate()
		changed := false
		for obj, n := range nodes {
			if r.local[obj] {
				continue
			}
			for ref := range n.refs {
				if r.resolve(ref) {
					r.local[obj] = true
					work = append(work, obj)
					changed = true
					break
				}
			}
		}
		if !changed {
			break
		}
	}

	var hiddenWork []*types.Func
	for obj := range r.hidden {
		hiddenWork = append(hiddenWork, obj)
	}
	for len(hiddenWork) > 0 {
		obj := hiddenWork[len(hiddenWork)-1]
		hiddenWork = hiddenWork[:len(hiddenWork)-1]
		for _, caller := range callers[obj] {
			if !r.hidden[caller] {
				r.hidden[caller] = true
				hiddenWork = append(hiddenWork, caller)
			}
		}
	}

	// Functions that don't reach the network carry the interface calls they and their callees make that
	// are still unresolved.
	unresolved := map[*types.Func]map[ifaceRef]bool{}
	r.unresolved = unresolved
	work = work[:0]
	for obj, n := range nodes {
		if r.local[obj] {
			r.network = true
			continue
		}
		set := map[ifaceRef]bool{}
		for ref := range n.refs {
			if len(set) < maxIfaceRefs && !r.resolve(ref) {
				set[ref] = true
			}
		}
		unresolved[obj] = set
		if len(set) > 0 {
			work = append(work, obj)
		}
	}
	for len(work) > 0 {
		obj := work[len(work)-1]
		work = work[:len(work)-1]
		for _, caller := range callers[obj] {
			set := unresolved[caller]
			if set == nil {
				continue
			}
			grew := false
			for ref := range unresolved[obj] {
				if len(set) < maxIfaceRefs && !set[ref] {
					set[ref] = true
					grew = true
				}
			}
			if grew {
				work = append(work, caller)
			}
		}
	}

	for obj := range nodes {
		if r.local[obj] {
			pass.ExportObjectFact(obj, &netFuncFact{Network: true})
		} else if refs := unresolved[obj]; len(refs) > 0 || r.hidden[obj] {
			fact := &netFuncFact{Hidden: r.hidden[obj]}
			for ref := range refs {
				fact.Ifaces = append(fact.Ifaces, ref)
			}
			sort.Slice(fact.Ifaces, func(i, j int) bool {
				a, b := fact.Ifaces[i], fact.Ifaces[j]
				if a.Ctx != b.Ctx {
					return a.Ctx
				}
				return a.Pkg+"."+a.Type+"."+a.Method < b.Pkg+"."+b.Type+"."+b.Method
			})
			if len(fact.Ifaces) > maxIfaceRefs {
				fact.Ifaces = fact.Ifaces[:maxIfaceRefs]
			}
			pass.ExportObjectFact(obj, fact)
		}
	}
	if !r.network {
		for _, imp := range pass.Pkg.Imports() {
			if r.pkgReaches(imp) {
				r.network = true
				break
			}
		}
	}
	if r.network {
		pass.ExportPackageFact(&netPkgFact{Network: true})
	}
	return r, nil
}

// reaches reports whether calling f can reach the network.
func (r *netReach) reaches(f *types.Func) bool {
	if r == nil || f == nil || f.Pkg() == nil {
		return false
	}
	f = f.Origin()
	if isNetworkPrimitive(f) {
		return true
	}
	if f.Pkg() == r.pass.Pkg {
		if ref, ok := r.ifaceRefOf(f); ok {
			return r.resolve(ref)
		}
		return r.local[f]
	}
	if ref, ok := r.ifaceRefOf(f); ok {
		return r.resolve(ref)
	}
	network, refs, _ := r.imported(f)
	if network {
		return true
	}
	for _, ref := range refs {
		if r.resolve(ref) {
			return true
		}
	}
	return false
}

// mightReach reports whether calling f can reach the network, or might: f takes a context, makes calls
// that can't be followed, and belongs to a network library or the module being linted. Libraries that
// keep a persistent connection write to it through io interfaces, func values and goroutines, so
// following alone misses most of them.
func (r *netReach) mightReach(f *types.Func, inModule bool) bool {
	if r.reaches(f) {
		return true
	}
	if r == nil || f == nil || f.Pkg() == nil {
		return false
	}
	f = f.Origin()
	sig, ok := f.Type().(*types.Signature)
	if !ok || !takesContext(sig) || !inModule && !r.pkgReaches(f.Pkg()) {
		return false
	}
	return r.isHidden(f)
}

// isHidden reports whether f makes calls that can't be followed, or interface calls that nothing
// visible from this package resolved.
func (r *netReach) isHidden(f *types.Func) bool {
	if ref, ok := r.ifaceRefOf(f); ok {
		return !r.implemented(ref)
	}
	if f.Pkg() == r.pass.Pkg {
		if r.hidden[f] {
			return true
		}
		for ref := range r.unresolved[f] {
			if r.hiddenRef(ref) {
				return true
			}
		}
		return false
	}
	if notFollowed(f.Pkg().Path()) {
		return false
	}
	var fact netFuncFact
	if !r.pass.ImportObjectFact(f, &fact) {
		return false
	}
	if fact.Hidden {
		return true
	}
	for _, ref := range fact.Ifaces {
		if r.hiddenRef(ref) {
			return true
		}
	}
	return false
}

// hiddenRef reports whether ref is a context-taking interface call that can't be followed: nothing
// visible from this package implements the interface.
func (r *netReach) hiddenRef(ref ifaceRef) bool {
	return ref.Ctx && !r.resolve(ref) && !r.implemented(ref)
}

// implemented reports whether any named type visible from this package implements ref's interface.
// If some do and none of them reach the network, the call is known not to.
func (r *netReach) implemented(ref ifaceRef) bool {
	r.mu.Lock()
	v, ok := r.implCache[ref]
	r.mu.Unlock()
	if ok {
		return v
	}
	iface := r.lookupIface(ref)
	found := false
	if iface != nil {
	search:
		for _, pkg := range r.pkgs {
			scope := pkg.Scope()
			for _, name := range scope.Names() {
				tn, ok := scope.Lookup(name).(*types.TypeName)
				if !ok || tn.IsAlias() {
					continue
				}
				if _, isIface := tn.Type().Underlying().(*types.Interface); isIface {
					continue
				}
				if types.Implements(types.NewPointer(tn.Type()), iface) {
					found = true
					break search
				}
			}
		}
	}
	r.mu.Lock()
	r.implCache[ref] = found
	r.mu.Unlock()
	return found
}

func (r *netReach) lookupIface(ref ifaceRef) *types.Interface {
	pkg := r.pkgs[ref.Pkg]
	if pkg == nil {
		return nil
	}
	tn, ok := pkg.Scope().Lookup(ref.Type).(*types.TypeName)
	if !ok {
		return nil
	}
	iface, _ := tn.Type().Underlying().(*types.Interface)
	return iface
}

// pkgReaches reports whether a package is a network library: it, or a package it imports, has
// functions that reach the network.
func (r *netReach) pkgReaches(pkg *types.Package) bool {
	if r == nil || pkg == nil {
		return false
	}
	if pkg == r.pass.Pkg {
		return r.network
	}
	switch pkg.Path() {
	case "net", "net/http", "crypto/tls":
		return true
	}
	if r.configured(pkg.Path()) {
		return true
	}
	if notFollowed(pkg.Path()) {
		return false
	}
	var fact netPkgFact
	return r.pass.ImportPackageFact(pkg, &fact)
}

// imported looks up a function from another package.
func (r *netReach) imported(f *types.Func) (network bool, refs []ifaceRef, hidden bool) {
	if f.Pkg() == nil {
		return false, nil, false
	}
	path := f.Pkg().Path()
	if isNetworkPrimitive(f) || r.configured(path) {
		return true, nil, false
	}
	if notFollowed(path) {
		return false, nil, false
	}
	var fact netFuncFact
	if !r.pass.ImportObjectFact(f, &fact) {
		return false, nil, false
	}
	return fact.Network, fact.Ifaces, fact.Hidden
}

func (r *netReach) configured(path string) bool {
	for _, prefix := range r.cfg.NetworkPackages {
		prefix = strings.TrimSuffix(prefix, "/...")
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}

// ifaceRefOf returns the interface method f is, if it's a method of a named interface in a package that
// is followed. Calls through standard library interfaces (io.Writer and the like) aren't resolved: almost
// every type implements them, and the network ones are covered by the primitives.
func (r *netReach) ifaceRefOf(f *types.Func) (ifaceRef, bool) {
	sig, ok := f.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return ifaceRef{}, false
	}
	named, ok := types.Unalias(sig.Recv().Type()).(*types.Named)
	if !ok {
		return ifaceRef{}, false
	}
	if _, ok := named.Underlying().(*types.Interface); !ok || named.Obj().Pkg() == nil {
		return ifaceRef{}, false
	}
	path := named.Obj().Pkg().Path()
	if notFollowed(path) {
		return ifaceRef{}, false
	}
	return ifaceRef{Pkg: path, Type: named.Obj().Name(), Method: f.Name()}, true
}

// resolve reports whether any method visible from this package that implements ref reaches the network.
func (r *netReach) resolve(ref ifaceRef) bool {
	r.mu.Lock()
	known := r.ifaces[ref]
	r.mu.Unlock()
	if known {
		return true
	}
	iface := r.lookupIface(ref)
	if iface == nil {
		return false
	}
	check := func(m *types.Func) bool {
		if m.Name() != ref.Method {
			return false
		}
		recv := m.Type().(*types.Signature).Recv().Type()
		if ptr, ok := recv.(*types.Pointer); ok {
			recv = ptr.Elem()
		}
		return types.Implements(types.NewPointer(recv), iface)
	}
	found := false
	for _, m := range r.impls {
		if check(m) {
			found = true
			break
		}
	}
	if !found {
		for m, network := range r.local {
			if network && isConcreteMethod(m) && check(m) {
				found = true
				break
			}
		}
	}
	if found {
		r.mu.Lock()
		r.ifaces[ref] = true
		r.mu.Unlock()
	}
	return found
}

func isConcreteMethod(f *types.Func) bool {
	if f == nil {
		return false
	}
	sig, ok := f.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return false
	}
	_, isIface := sig.Recv().Type().Underlying().(*types.Interface)
	return !isIface
}

// notFollowed reports whether calls into this package aren't followed: the standard library (whose
// network entry points are matched directly by isNetworkPrimitive), bridgev2, whose errors come from the
// bridge's own homeserver rather than the remote network, and go.mau.fi/util (database helpers and the
// like). Standard library paths are the ones without a dot in the first element.
func notFollowed(path string) bool {
	first, _, _ := strings.Cut(path, "/")
	if !strings.Contains(first, ".") {
		return true
	}
	return path == pathBridgev2 || strings.HasPrefix(path, pathBridgev2+"/") || path == "go.mau.fi/util" || strings.HasPrefix(path, "go.mau.fi/util/")
}

// isNetworkPrimitive matches the standard library calls that do network I/O: an HTTP round trip, a dial,
// or a read or write on a connection.
func isNetworkPrimitive(f *types.Func) bool {
	if f.Pkg() == nil {
		return false
	}
	if isHTTPRoundTrip(f) {
		return true
	}
	path := f.Pkg().Path()
	if path != "net" && path != "crypto/tls" && path != "net/http" {
		return false
	}
	sig := f.Type().(*types.Signature)
	name := f.Name()
	if path == "net/http" {
		if sig.Recv() == nil {
			return false
		}
		recv := recvTypeName(sig)
		return recv == "Client" && (name == "Get" || name == "Head" || name == "Post" || name == "PostForm")
	}
	if strings.HasPrefix(name, "Dial") {
		return true
	}
	if sig.Recv() == nil {
		return false
	}
	return strings.HasPrefix(name, "Read") || strings.HasPrefix(name, "Write") || name == "Handshake" || name == "HandshakeContext"
}

func recvTypeName(sig *types.Signature) string {
	t := sig.Recv().Type()
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	if named, ok := types.Unalias(t).(*types.Named); ok {
		return named.Obj().Name()
	}
	return ""
}

func asFuncLit(e ast.Expr) *ast.FuncLit {
	lit, _ := unparen(e).(*ast.FuncLit)
	return lit
}

// isBufferedConnIO matches a read or write on a bufio.Reader or Writer kept in a struct field, which is
// how websocket and other framing libraries talk to their connection.
func isBufferedConnIO(f *types.Func, call *ast.CallExpr) bool {
	if f.Pkg() == nil || f.Pkg().Path() != "bufio" {
		return false
	}
	sig, ok := f.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return false
	}
	sel, ok := unparen(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	if _, ok := unparen(sel.X).(*ast.SelectorExpr); !ok {
		return false
	}
	name := f.Name()
	return strings.HasPrefix(name, "Read") || strings.HasPrefix(name, "Write") || name == "Flush" || name == "Peek"
}

func passesContext(info *types.Info, call *ast.CallExpr) bool {
	for _, arg := range call.Args {
		if isNamed(info.TypeOf(arg), "context", "Context") {
			return true
		}
	}
	return false
}

// receivedChans returns the channel variables body receives from.
func receivedChans(info *types.Info, body *ast.BlockStmt) map[types.Object]bool {
	out := map[types.Object]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		if u, ok := n.(*ast.UnaryExpr); ok && u.Op == token.ARROW {
			if id, ok := unparen(u.X).(*ast.Ident); ok && info.Uses[id] != nil {
				out[info.Uses[id]] = true
			}
		}
		return true
	})
	return out
}

// sendsTo reports whether body sends on one of chans.
func sendsTo(info *types.Info, body *ast.BlockStmt, chans map[types.Object]bool) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if send, ok := n.(*ast.SendStmt); ok {
			if id, ok := unparen(send.Chan).(*ast.Ident); ok && chans[info.Uses[id]] {
				found = true
			}
		}
		return !found
	})
	return found
}
