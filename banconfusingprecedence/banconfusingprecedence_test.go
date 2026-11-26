package main

import (
	"go/ast"
	"go/parser"
	"testing"
)

func TestIsConfusing(t *testing.T) {
	cases := map[string]bool{
		"a && b || c":      true,
		"a || b && c":      true,
		"(a && b) || c":    false,
		"a || (b && c)":    false,
		"a && b && c":      false,
		"a || b || c":      false,
		"a == b && c != d": false,
		"a&b == 0":         false,
		"a | b&c":          true,
		"a ^ b | c":        true,
		"a | b | c":        false,
		"a&b + c":          true,
		"a + b*c":          false,
		"a*b - c/d":        false,
		"1<<n - 1":         true,
		"a & b << c":       true,
		"a | b<<8":         false,
		"a<<8 | b":         false,
		"a >> b & c":       true,
		"a &^ b | c":       true,
	}
	for src, want := range cases {
		expr, err := parser.ParseExpr(src)
		if err != nil {
			t.Fatalf("parse %q: %v", src, err)
		}
		got := false
		ast.Inspect(expr, func(n ast.Node) bool {
			bin, ok := n.(*ast.BinaryExpr)
			if !ok {
				return true
			}
			for _, operand := range []ast.Expr{bin.X, bin.Y} {
				if child, ok := operand.(*ast.BinaryExpr); ok && isConfusing(bin.Op, child.Op) {
					got = true
				}
			}
			return true
		})
		if got != want {
			t.Errorf("%q: got %v, want %v", src, got, want)
		}
	}
}
