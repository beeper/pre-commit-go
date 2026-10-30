package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/tools/go/packages"
)

const (
	COLOR_BOLD  = "\033[1m"
	COLOR_RED   = "\033[31m"
	COLOR_RESET = "\033[0m"
)

type tagKey struct {
	file   string
	offset int
}

type edit struct {
	start, end int
	text       string
}

var scalarBuiltins = map[string]bool{
	"bool":    true,
	"int":     true,
	"int8":    true,
	"int16":   true,
	"int32":   true,
	"int64":   true,
	"uint":    true,
	"uint8":   true,
	"uint16":  true,
	"uint32":  true,
	"uint64":  true,
	"uintptr": true,
	"float32": true,
	"float64": true,
	"byte":    true,
	"rune":    true,
}

func main() {
	var files []string
	for _, file := range os.Args[1:] {
		if strings.HasSuffix(file, ".go") {
			files = append(files, file)
		}
	}
	typed := loadTypedFields(files)

	var found bool
	for _, file := range files {
		if processFile(file, typed) {
			found = true
		}
	}
	if found {
		os.Exit(1)
	}
}

func findModuleRoot(dir string) string {
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// loadTypedFields type checks the packages containing the given files and returns whether each
// struct field with a tag has a numeric or boolean underlying type. Fields that couldn't be type
// checked are missing from the map, and processFile falls back to a syntactic check for them.
func loadTypedFields(files []string) map[tagKey]bool {
	dirsByModule := make(map[string][]string)
	for _, file := range files {
		contents, err := os.ReadFile(file)
		if err != nil || !bytes.Contains(contents, []byte("omitempty")) {
			continue
		}
		absFile, err := filepath.Abs(file)
		if err != nil {
			continue
		}
		dir := filepath.Dir(absFile)
		root := findModuleRoot(dir)
		if root == "" {
			continue
		}
		rel, err := filepath.Rel(root, dir)
		if err != nil {
			continue
		}
		pattern := "./" + filepath.ToSlash(rel)
		if !slices.Contains(dirsByModule[root], pattern) {
			dirsByModule[root] = append(dirsByModule[root], pattern)
		}
	}

	result := make(map[tagKey]bool)
	for root, patterns := range dirsByModule {
		pkgs, err := packages.Load(&packages.Config{
			Mode:  packages.LoadSyntax,
			Dir:   root,
			Tests: true,
		}, patterns...)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load packages in %s, falling back to syntactic checks: %v\n", root, err)
			continue
		}
		for _, pkg := range pkgs {
			if pkg.TypesInfo == nil {
				continue
			}
			for _, file := range pkg.Syntax {
				ast.Inspect(file, func(node ast.Node) bool {
					st, ok := node.(*ast.StructType)
					if !ok {
						return true
					}
					for _, field := range st.Fields.List {
						if field.Tag == nil {
							continue
						}
						typ := pkg.TypesInfo.TypeOf(field.Type)
						if typ == nil || typ == types.Typ[types.Invalid] {
							continue
						}
						pos := pkg.Fset.PositionFor(field.Tag.Pos(), false)
						result[tagKey{file: pos.Filename, offset: pos.Offset}] = isScalarType(typ)
					}
					return true
				})
			}
		}
	}
	return result
}

// encoding/json/v2 only treats null, "", {} and [] as empty, so omitempty never omits
// numbers or booleans there. omitzero behaves the same in v1 and v2.
func isScalarType(typ types.Type) bool {
	if _, ok := typ.(*types.TypeParam); ok {
		return false
	}
	basic, ok := typ.Underlying().(*types.Basic)
	return ok && basic.Info()&(types.IsNumeric|types.IsBoolean) != 0
}

// collectTypeDecls returns the non-generic type declarations in the given file and other files
// of the same package in its directory, for resolving field types without type information.
func collectTypeDecls(file string, parsed *ast.File) map[string]ast.Expr {
	decls := make(map[string]ast.Expr)
	addDecls := func(f *ast.File) {
		for _, decl := range f.Decls {
			genDecl, ok := decl.(*ast.GenDecl)
			if !ok || genDecl.Tok != token.TYPE {
				continue
			}
			for _, spec := range genDecl.Specs {
				typeSpec := spec.(*ast.TypeSpec)
				if typeSpec.TypeParams == nil {
					decls[typeSpec.Name.Name] = typeSpec.Type
				}
			}
		}
	}
	siblings, _ := filepath.Glob(filepath.Join(filepath.Dir(file), "*.go"))
	fset := token.NewFileSet()
	for _, sibling := range siblings {
		if filepath.Base(sibling) == filepath.Base(file) {
			continue
		}
		f, err := parser.ParseFile(fset, sibling, nil, parser.SkipObjectResolution)
		if err == nil && f.Name.Name == parsed.Name.Name {
			addDecls(f)
		}
	}
	addDecls(parsed)
	return decls
}

func isScalarExpr(expr ast.Expr, decls map[string]ast.Expr, depth int) bool {
	if depth > 16 {
		return false
	}
	switch e := expr.(type) {
	case *ast.ParenExpr:
		return isScalarExpr(e.X, decls, depth+1)
	case *ast.Ident:
		if decl, ok := decls[e.Name]; ok {
			return isScalarExpr(decl, decls, depth+1)
		}
		return scalarBuiltins[e.Name]
	}
	return false
}

// findTagValue returns the start and end index of the quoted value of key in a struct tag,
// using the same parsing rules as reflect.StructTag.Lookup.
func findTagValue(tag, key string) (int, int, bool) {
	i := 0
	for i < len(tag) {
		for i < len(tag) && tag[i] == ' ' {
			i++
		}
		if i >= len(tag) {
			break
		}
		nameStart := i
		for i < len(tag) && tag[i] > ' ' && tag[i] != ':' && tag[i] != '"' && tag[i] != 0x7f {
			i++
		}
		if i == nameStart || i+1 >= len(tag) || tag[i] != ':' || tag[i+1] != '"' {
			break
		}
		name := tag[nameStart:i]
		i++
		valueStart := i
		i++
		for i < len(tag) && tag[i] != '"' {
			if tag[i] == '\\' {
				i++
			}
			i++
		}
		if i >= len(tag) {
			break
		}
		i++
		if name == key {
			return valueStart, i, true
		}
	}
	return 0, 0, false
}

func replaceOmitEmpty(jsonTag string) string {
	parts := strings.Split(jsonTag, ",")
	hasOmitZero := slices.Contains(parts[1:], "omitzero")
	newParts := []string{parts[0]}
	for _, opt := range parts[1:] {
		if opt == "omitempty" {
			if hasOmitZero {
				continue
			}
			opt = "omitzero"
			hasOmitZero = true
		}
		newParts = append(newParts, opt)
	}
	return strings.Join(newParts, ",")
}

// fixTag returns the replacement source for a struct tag literal, or false if it doesn't
// have a json tag with omitempty.
func fixTag(literal string) (string, bool) {
	tag, err := strconv.Unquote(literal)
	if err != nil {
		return "", false
	}
	jsonTag, ok := reflect.StructTag(tag).Lookup("json")
	if !ok || !slices.Contains(strings.Split(jsonTag, ",")[1:], "omitempty") {
		return "", false
	}
	start, end, ok := findTagValue(tag, "json")
	if !ok {
		return "", false
	}
	newTag := tag[:start] + strconv.Quote(replaceOmitEmpty(jsonTag)) + tag[end:]
	if strings.HasPrefix(literal, "`") && !strings.Contains(newTag, "`") {
		return "`" + newTag + "`", true
	}
	return strconv.Quote(newTag), true
}

func processFile(file string, typed map[tagKey]bool) bool {
	stat, err := os.Stat(file)
	if err != nil {
		panic(err)
	}
	contents, err := os.ReadFile(file)
	if err != nil {
		panic(err)
	}
	if !bytes.Contains(contents, []byte("omitempty")) {
		return false
	}
	absFile, err := filepath.Abs(file)
	if err != nil {
		panic(err)
	}

	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, file, contents, parser.SkipObjectResolution)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse %s: %v\n", file, err)
		return false
	}

	var decls map[string]ast.Expr
	var edits []edit
	ast.Inspect(parsed, func(node ast.Node) bool {
		st, ok := node.(*ast.StructType)
		if !ok {
			return true
		}
		for _, field := range st.Fields.List {
			if field.Tag == nil {
				continue
			}
			newLiteral, ok := fixTag(field.Tag.Value)
			if !ok {
				continue
			}
			pos := fset.Position(field.Tag.Pos())
			scalar, ok := typed[tagKey{file: absFile, offset: pos.Offset}]
			if !ok {
				if decls == nil {
					decls = collectTypeDecls(file, parsed)
				}
				scalar = isScalarExpr(field.Type, decls, 0)
			}
			if !scalar {
				continue
			}
			edits = append(edits, edit{
				start: pos.Offset,
				end:   pos.Offset + len(field.Tag.Value),
				text:  newLiteral,
			})
		}
		return true
	})
	if len(edits) == 0 {
		return false
	}

	fmt.Printf("\n%s%s%s\n", COLOR_BOLD, file, COLOR_RESET)
	sort.Slice(edits, func(i, j int) bool {
		return edits[i].start < edits[j].start
	})
	lineStarts := []int{0}
	for i, b := range contents {
		if b == '\n' {
			lineStarts = append(lineStarts, i+1)
		}
	}
	printedLines := make(map[int]bool)
	for _, e := range edits {
		line := sort.SearchInts(lineStarts, e.start+1) - 1
		if printedLines[line] {
			continue
		}
		printedLines[line] = true
		lineEnd := len(contents)
		if line+1 < len(lineStarts) {
			lineEnd = lineStarts[line+1] - 1
		}
		lineText := string(contents[lineStarts[line]:lineEnd])
		fmt.Printf("%d: %s\n", line+1, strings.ReplaceAll(lineText, "omitempty", COLOR_BOLD+COLOR_RED+"omitempty"+COLOR_RESET))
	}

	var out bytes.Buffer
	prev := 0
	for _, e := range edits {
		out.Write(contents[prev:e.start])
		out.WriteString(e.text)
		prev = e.end
	}
	out.Write(contents[prev:])
	err = os.WriteFile(file, out.Bytes(), stat.Mode().Perm())
	if err != nil {
		panic(err)
	}
	return true
}
