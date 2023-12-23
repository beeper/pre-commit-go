package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"slices"
	"strings"
)

const (
	COLOR_BOLD  = "\033[1m"
	COLOR_RED   = "\033[31m"
	COLOR_RESET = "\033[0m"
)

func checkFile(filename string) (msgfPositions []token.Position) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filename, nil, parser.ParseComments)
	if err != nil {
		panic(err)
	}

	ast.Inspect(f, func(n ast.Node) bool {
		if callExpr, ok := n.(*ast.CallExpr); ok {
			if selector, ok := callExpr.Fun.(*ast.SelectorExpr); ok {
				if selector.Sel.Name == "Msgf" {
					pos := fset.Position(n.Pos())
					msgfPositions = append(msgfPositions, pos)
				}
			}
		}
		return true
	})

	ignoreLines := map[int]struct{}{}
	for _, comment := range f.Comments {
		if strings.Contains(comment.Text(), "zerolog-allow-msgf") {
			commentLine := fset.Position(comment.Pos()).Line
			ignoreLines[commentLine] = struct{}{}
		}
	}

	if len(ignoreLines) == 0 {
		return msgfPositions
	}

	msgfPositions = slices.DeleteFunc(msgfPositions, func(pos token.Position) bool {
		_, ok := ignoreLines[pos.Line]
		return ok
	})
	return
}

func main() {
	found_msgf := false
	msgfLines := map[string][]token.Position{}
	for _, file := range os.Args[1:] {
		msgfLines[file] = checkFile(file)
	}

	for file, positions := range msgfLines {
		if len(positions) == 0 {
			continue
		}

		contents, err := os.ReadFile(file)
		if err != nil {
			panic(err)
		}
		lines := bytes.Split(contents, []byte("\n"))

		fmt.Printf("%s%s:%s\n", COLOR_BOLD, file, COLOR_RESET)
		for _, pos := range positions {
			line := lines[pos.Line-1]
			msgfIdx := bytes.Index(line, []byte("Msgf"))
			fmt.Printf("%d: %s%s%sMsgf%s%s\n", pos.Line, line[:msgfIdx], COLOR_BOLD, COLOR_RED, COLOR_RESET, line[msgfIdx+4:])
		}
	}

	if found_msgf {
		os.Exit(1)
	}
}
