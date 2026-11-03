package rules

import (
	"go/ast"
	"go/types"
)

// statusChain is a bridgev2.MessageStatus built by WrapErrorInStatus(...).With...() calls or a literal.
type statusChain struct {
	outer   *ast.CallExpr
	root    ast.Expr
	known   bool     // root is WrapErrorInStatus or a MessageStatus literal, so fields not set in the chain are defaults
	inner   ast.Expr // the error passed to WrapErrorInStatus or InternalError in a literal
	methods map[string][]ast.Expr
	order   []string
	fields  map[string]ast.Expr
}

func (c *statusChain) has(name string) bool {
	_, ok := c.methods[name]
	return ok
}

func (c *statusChain) node() ast.Node {
	if c.outer != nil {
		return c.outer
	}
	return c.root
}

func isMessageStatus(t types.Type) bool {
	return isNamed(t, pathBridgev2, "MessageStatus")
}

// parseStatusChain parses e if it's a MessageStatus expression. Nested chain calls are recorded in seen.
func parseStatusChain(info *types.Info, e ast.Expr, seen map[ast.Node]bool) *statusChain {
	if !isMessageStatus(info.TypeOf(e)) {
		return nil
	}
	c := &statusChain{methods: map[string][]ast.Expr{}, fields: map[string]ast.Expr{}}
	if call, ok := e.(*ast.CallExpr); ok {
		c.outer = call
	}
	cur := unparen(e)
	for {
		call, ok := cur.(*ast.CallExpr)
		if !ok {
			break
		}
		seen[call] = true
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if ok && isMessageStatus(info.TypeOf(sel.X)) {
			if _, exists := c.methods[sel.Sel.Name]; !exists {
				c.methods[sel.Sel.Name] = call.Args
			}
			c.order = append(c.order, sel.Sel.Name)
			cur = unparen(sel.X)
			continue
		}
		if isPkgFunc(calleeObj(info, call), pathBridgev2, "WrapErrorInStatus") && len(call.Args) == 1 {
			c.known = true
			c.inner = call.Args[0]
		}
		break
	}
	if lit, ok := cur.(*ast.CompositeLit); ok {
		c.known = true
		for _, elt := range lit.Elts {
			if kv, ok := elt.(*ast.KeyValueExpr); ok {
				if key, ok := kv.Key.(*ast.Ident); ok {
					c.fields[key.Name] = kv.Value
				}
			}
		}
		c.inner = c.fields["InternalError"]
	}
	c.root = cur
	return c
}

// reason returns the name of the event.MessageStatusReason constant the chain sets, if any.
func (c *statusChain) reason(info *types.Info) (string, bool) {
	var e ast.Expr
	if args, ok := c.methods["WithErrorReason"]; ok && len(args) == 1 {
		e = args[0]
	} else if v, ok := c.fields["ErrorReason"]; ok {
		e = v
	} else {
		return "", false
	}
	if sel, ok := unparen(e).(*ast.SelectorExpr); ok {
		return sel.Sel.Name, true
	}
	if id, ok := unparen(e).(*ast.Ident); ok {
		return id.Name, true
	}
	return "?", true
}

func (c *statusChain) hasStatus() bool {
	_, lit := c.fields["Status"]
	return c.has("WithStatus") || lit
}

func (c *statusChain) message() (ast.Expr, bool) {
	if args, ok := c.methods["WithMessage"]; ok && len(args) == 1 {
		return args[0], true
	}
	if v, ok := c.fields["Message"]; ok {
		return v, true
	}
	return nil, false
}

func (c *statusChain) certain(info *types.Info) (bool, bool) {
	var e ast.Expr
	if args, ok := c.methods["WithIsCertain"]; ok && len(args) == 1 {
		e = args[0]
	} else if v, ok := c.fields["IsCertain"]; ok {
		e = v
	} else {
		return false, false
	}
	if id, ok := unparen(e).(*ast.Ident); ok {
		switch id.Name {
		case "true":
			return true, true
		case "false":
			return false, true
		}
	}
	return false, false
}

// eachStatusChain calls fn for every outermost MessageStatus chain in the package.
func eachStatusChain(pi *pkgInfo, fn func(c *statusChain)) {
	seen := map[ast.Node]bool{}
	for _, f := range pi.pass.Files {
		ast.Inspect(f, func(n ast.Node) bool {
			e, ok := n.(ast.Expr)
			if !ok || seen[n] {
				return true
			}
			switch e.(type) {
			case *ast.CallExpr, *ast.CompositeLit:
			default:
				return true
			}
			if c := parseStatusChain(pi.pass.TypesInfo, e, seen); c != nil {
				seen[c.root] = true
				if c.known || len(c.methods) > 0 {
					fn(c)
				}
			}
			return true
		})
	}
}
