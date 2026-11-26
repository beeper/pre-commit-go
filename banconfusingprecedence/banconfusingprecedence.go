package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"regexp"
	"strings"
)

var ignoreCommentRegex = regexp.MustCompile(`//\s*allow-confusing-precedence`)

type opClass int

const (
	classOther opClass = iota
	classLogical
	classBitwise
	classShift
	classArithmetic
)

func classify(op token.Token) opClass {
	switch op {
	case token.LAND, token.LOR:
		return classLogical
	case token.AND, token.OR, token.XOR, token.AND_NOT:
		return classBitwise
	case token.SHL, token.SHR:
		return classShift
	case token.ADD, token.SUB, token.MUL, token.QUO, token.REM:
		return classArithmetic
	default:
		return classOther
	}
}

// isConfusing reports whether an unparenthesized child operation inside a parent
// operation is easy to misread. Comparisons and pure arithmetic are always allowed.
func isConfusing(parent, child token.Token) bool {
	if parent == child {
		return false
	}
	pc, cc := classify(parent), classify(child)
	switch {
	case pc == classLogical && cc == classLogical:
		// a && b || c
		return true
	case pc == classBitwise && cc == classBitwise:
		// a | b & c, a & b ^ c
		return true
	case pc == classBitwise && cc == classArithmetic,
		pc == classArithmetic && cc == classBitwise:
		// a & b + c is (a & b) + c in Go but a & (b + c) in C.
		// Shifts mixed with arithmetic (1<<n - 1) are allowed, gofmt spacing makes them clear.
		return true
	case pc == classShift && cc == classBitwise,
		(parent == token.AND || parent == token.AND_NOT) && cc == classShift:
		// a & b << c is (a & b) << c in Go but a & (b << c) in C.
		// a | b<<c parses the same way in both, so it's allowed.
		return true
	case pc == classShift && cc == classShift:
		// a << b >> c
		return true
	}
	return false
}

func exprString(fset *token.FileSet, expr ast.Expr) string {
	var buf bytes.Buffer
	_ = printer.Fprint(&buf, fset, expr)
	return buf.String()
}

func main() {
	var found bool
	for _, filename := range os.Args[1:] {
		src, err := os.ReadFile(filename)
		if err != nil {
			panic(fmt.Errorf("unable to read %s: %w", filename, err))
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, filename, src, parser.SkipObjectResolution)
		if err != nil {
			fmt.Printf("Failed to parse %s: %v\n", filename, err)
			found = true
			continue
		}
		lines := strings.Split(string(src), "\n")
		ast.Inspect(file, func(n ast.Node) bool {
			bin, ok := n.(*ast.BinaryExpr)
			if !ok {
				return true
			}
			for _, operand := range []ast.Expr{bin.X, bin.Y} {
				child, ok := operand.(*ast.BinaryExpr)
				if !ok || !isConfusing(bin.Op, child.Op) {
					continue
				}
				pos := fset.Position(child.OpPos)
				if pos.Line-1 < len(lines) && ignoreCommentRegex.MatchString(lines[pos.Line-1]) {
					continue
				}
				fmt.Printf(
					"%s: mixing %s and %s without parentheses, wrap (%s) in parentheses\n",
					pos, bin.Op, child.Op, exprString(fset, child),
				)
				found = true
			}
			return true
		})
	}
	if found {
		os.Exit(1)
	}
}
