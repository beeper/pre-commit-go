package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"slices"
	"strings"
)

const (
	COLOR_BOLD  = "\033[1m"
	COLOR_RED   = "\033[31m"
	COLOR_RESET = "\033[0m"
)

type methodPosition struct {
	Pos    token.Position
	Method string
}

func checkFile(filename string) (methodPositions []methodPosition) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filename, nil, parser.ParseComments)
	if err != nil {
		panic(err)
	}

	ast.Inspect(f, func(n ast.Node) bool {
		if basicLit, ok := n.(*ast.BasicLit); !ok {
			return true
		} else if basicLit.Kind != token.STRING {
			return true
		} else {
			strVal := basicLit.Value[1 : len(basicLit.Value)-1]
			switch strVal {
			case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch,
				http.MethodDelete, http.MethodConnect, http.MethodOptions, http.MethodTrace:
				methodPositions = append(methodPositions, methodPosition{
					Pos:    fset.Position(n.Pos()),
					Method: strVal,
				})
			}
		}
		return true
	})

	ignoreLines := map[int]struct{}{}
	for _, comment := range f.Comments {
		if strings.Contains(comment.Text(), "allow-hardcoded-http-method") {
			commentLine := fset.Position(comment.Pos()).Line
			ignoreLines[commentLine] = struct{}{}
		}
	}

	if len(ignoreLines) == 0 {
		return methodPositions
	}

	methodPositions = slices.DeleteFunc(methodPositions, func(mp methodPosition) bool {
		_, ok := ignoreLines[mp.Pos.Line]
		return ok
	})
	return
}

func main() {
	var foundLiteralMethod bool
	msgfLines := map[string][]methodPosition{}
	for _, file := range os.Args[1:] {
		msgfLines[file] = checkFile(file)
	}

	for file, methodPoses := range msgfLines {
		if len(methodPoses) == 0 {
			continue
		}
		foundLiteralMethod = true

		contents, err := os.ReadFile(file)
		if err != nil {
			panic(err)
		}
		lines := bytes.Split(contents, []byte("\n"))

		fmt.Printf("\n%s%s%s\n", COLOR_BOLD, file, COLOR_RESET)
		for _, mp := range methodPoses {
			line := lines[mp.Pos.Line-1]
			idx := bytes.Index(line, []byte(mp.Method))
			if idx < 0 {
				panic(fmt.Errorf("method %s not found in line %d", mp.Method, mp.Pos.Line))
			}
			fmt.Printf(`%d: %s%s%s"%s"%s%s
		use http.Method%c%s instead`,
				mp.Pos.Line, line[:idx-1], COLOR_BOLD, COLOR_RED, mp.Method, COLOR_RESET, line[idx+1+len(mp.Method):],
				mp.Method[0], strings.ToLower(mp.Method[1:]))
			fmt.Printf("\n")
		}
	}

	if foundLiteralMethod {
		os.Exit(1)
	}
}
