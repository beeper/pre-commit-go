// Command bridgelint checks mautrix bridgev2 bridges for the error-reporting and reliability
// mistakes found in Beeper's bridge audits. See README.md for the rules.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/checker"
	"golang.org/x/tools/go/packages"

	"github.com/beeper/pre-commit-go/bridgelint/rules"
)

const (
	colorBold   = "\033[1m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorReset  = "\033[0m"
)

var (
	verbose       = flag.Bool("verbose", false, "also show info-level findings")
	configPath    = flag.String("config", "", "path to .bridgelint.yaml (default: nearest one above each package)")
	baselinePath  = flag.String("baseline", "", "ignore findings recorded in this baseline file")
	writeBaseline = flag.Bool("write-baseline", false, "write all current findings to the -baseline file and exit 0")
	applyFixes    = flag.Bool("fix", false, "apply suggested fixes for reported findings")
	includeTests  = flag.Bool("tests", false, "also analyse _test.go files")
	noColor       = flag.Bool("no-color", os.Getenv("NO_COLOR") != "", "disable colored output")
	listRules     = flag.Bool("rules", false, "list rules and exit")
)

type finding struct {
	rule     string
	severity rules.Severity
	pos      token.Position
	message  string
	snippet  string
	diag     analysis.Diagnostic
	fset     *token.FileSet
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: bridgelint [flags] [packages]\n\nPackages default to ./...\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if *listRules {
		printRules()
		return
	}
	rules.ConfigOverride = *configPath
	patterns := flag.Args()
	if len(patterns) == 0 {
		patterns = []string{"./..."}
	}
	os.Exit(run(patterns))
}

func printRules() {
	ids := make([]string, 0, len(rules.Rules))
	for id := range rules.Rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		r := rules.Rules[id]
		fmt.Printf("%-7s %-8s %s\n", r.ID, r.Severity, r.Title)
	}
}

func run(patterns []string) int {
	cfg := &packages.Config{Mode: packages.LoadSyntax | packages.NeedModule, Tests: *includeTests}
	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bridgelint: %v\n", err)
		return 2
	}
	if n := packages.PrintErrors(pkgs); n > 0 {
		fmt.Fprintf(os.Stderr, "bridgelint: %d package loading errors\n", n)
		return 2
	}
	for _, pkg := range pkgs {
		for k := range rules.CollectHumanErrorKeys(pkg.TypesInfo, pkg.Syntax) {
			rules.ModuleHumanErrorKeys[k] = true
		}
	}
	graph, err := checker.Analyze(rules.Analyzers, pkgs, &checker.Options{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "bridgelint: %v\n", err)
		return 2
	}

	cwd, _ := os.Getwd()
	seen := map[string]bool{}
	var findings []finding
	failed := false
	for act := range graph.All() {
		if !act.IsRoot {
			continue
		}
		if act.Err != nil {
			fmt.Fprintf(os.Stderr, "bridgelint: %s: %v\n", act, act.Err)
			failed = true
			continue
		}
		fset := act.Package.Fset
		for _, d := range act.Diagnostics {
			id, sev := rules.SplitCategory(d.Category)
			pos := fset.Position(d.Pos)
			if rel, err := filepath.Rel(cwd, pos.Filename); err == nil && !strings.HasPrefix(rel, "..") {
				pos.Filename = rel
			}
			key := fmt.Sprintf("%s:%d:%d:%s", pos.Filename, pos.Line, pos.Column, d.Message)
			if seen[key] {
				continue
			}
			seen[key] = true
			findings = append(findings, finding{
				rule: id, severity: sev, pos: pos, message: d.Message,
				snippet: lineText(fset.Position(d.Pos)), diag: d, fset: fset,
			})
		}
	}
	if failed {
		return 2
	}
	sort.Slice(findings, func(i, j int) bool {
		a, b := findings[i].pos, findings[j].pos
		if a.Filename != b.Filename {
			return a.Filename < b.Filename
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Column < b.Column
	})

	if *writeBaseline {
		if *baselinePath == "" {
			fmt.Fprintln(os.Stderr, "bridgelint: -write-baseline needs -baseline")
			return 2
		}
		if err := saveBaseline(*baselinePath, findings); err != nil {
			fmt.Fprintf(os.Stderr, "bridgelint: %v\n", err)
			return 2
		}
		fmt.Printf("bridgelint: wrote %d findings to %s\n", len(findings), *baselinePath)
		return 0
	}
	if *baselinePath != "" {
		findings, err = filterBaseline(*baselinePath, findings)
		if err != nil {
			fmt.Fprintf(os.Stderr, "bridgelint: %v\n", err)
			return 2
		}
	}

	counts := map[rules.Severity]int{}
	var shown []finding
	for _, f := range findings {
		if f.severity == rules.SeverityInfo && !*verbose {
			continue
		}
		counts[f.severity]++
		shown = append(shown, f)
		printFinding(f)
	}
	if *applyFixes {
		if err := fix(shown); err != nil {
			fmt.Fprintf(os.Stderr, "bridgelint: applying fixes: %v\n", err)
			return 2
		}
	}
	if len(shown) > 0 {
		fmt.Printf("\n%d errors, %d warnings", counts[rules.SeverityError], counts[rules.SeverityWarning])
		if *verbose {
			fmt.Printf(", %d info", counts[rules.SeverityInfo])
		}
		fmt.Println()
	}
	if counts[rules.SeverityError] > 0 {
		return 1
	}
	return 0
}

func color(c, s string) string {
	if *noColor {
		return s
	}
	return c + s + colorReset
}

func printFinding(f finding) {
	sevColor := map[rules.Severity]string{rules.SeverityError: colorRed, rules.SeverityWarning: colorYellow, rules.SeverityInfo: colorBlue}[f.severity]
	fmt.Printf("%s %s %s\n", color(colorBold, f.pos.String()+":"), color(sevColor, string(f.severity)), f.message)
	if f.snippet != "" {
		fmt.Printf("    %s\n", strings.TrimSpace(f.snippet))
	}
}

var fileCache = map[string][]string{}

func lineText(pos token.Position) string {
	lines, ok := fileCache[pos.Filename]
	if !ok {
		data, err := os.ReadFile(pos.Filename)
		if err == nil {
			lines = strings.Split(string(data), "\n")
		}
		fileCache[pos.Filename] = lines
	}
	if pos.Line < 1 || pos.Line > len(lines) {
		return ""
	}
	return lines[pos.Line-1]
}

type baselineEntry struct {
	Rule        string `json:"rule"`
	File        string `json:"file"`
	SnippetHash string `json:"snippet_hash"`
	Count       int    `json:"count"`
}

type baselineFile struct {
	Version  int             `json:"version"`
	Findings []baselineEntry `json:"findings"`
}

func baselineKey(f finding) baselineEntry {
	sum := sha256.Sum256([]byte(strings.Join(strings.Fields(f.snippet), " ")))
	return baselineEntry{Rule: f.rule, File: filepath.ToSlash(f.pos.Filename), SnippetHash: hex.EncodeToString(sum[:8])}
}

func saveBaseline(path string, findings []finding) error {
	counts := map[baselineEntry]int{}
	var order []baselineEntry
	for _, f := range findings {
		k := baselineKey(f)
		if counts[k] == 0 {
			order = append(order, k)
		}
		counts[k]++
	}
	out := baselineFile{Version: 1}
	for _, k := range order {
		k2 := k
		k2.Count = counts[k]
		out.Findings = append(out.Findings, k2)
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

func filterBaseline(path string, findings []finding) ([]finding, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return findings, nil
	} else if err != nil {
		return nil, err
	}
	var bf baselineFile
	if err := json.Unmarshal(data, &bf); err != nil {
		return nil, fmt.Errorf("parsing baseline %s: %w", path, err)
	}
	budget := map[baselineEntry]int{}
	for _, e := range bf.Findings {
		count := e.Count
		e.Count = 0
		budget[e] += max(count, 1)
	}
	var out []finding
	for _, f := range findings {
		k := baselineKey(f)
		if budget[k] > 0 {
			budget[k]--
			continue
		}
		out = append(out, f)
	}
	return out, nil
}

type edit struct {
	start, end int
	text       []byte
}

func fix(findings []finding) error {
	byFile := map[string][]edit{}
	for _, f := range findings {
		if len(f.diag.SuggestedFixes) == 0 {
			continue
		}
		for _, te := range f.diag.SuggestedFixes[0].TextEdits {
			start := f.fset.Position(te.Pos)
			end := start
			if te.End.IsValid() {
				end = f.fset.Position(te.End)
			}
			byFile[start.Filename] = append(byFile[start.Filename], edit{start.Offset, end.Offset, te.NewText})
		}
	}
	for name, edits := range byFile {
		data, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		sort.Slice(edits, func(i, j int) bool { return edits[i].start > edits[j].start })
		lastStart := len(data) + 1
		applied := 0
		for _, e := range edits {
			if e.end > lastStart {
				continue // overlaps an edit already applied
			}
			data = append(data[:e.start:e.start], append(append([]byte{}, e.text...), data[e.end:]...)...)
			lastStart = e.start
			applied++
		}
		if err := os.WriteFile(name, data, 0o644); err != nil {
			return err
		}
		fmt.Printf("bridgelint: applied %d fixes to %s\n", applied, name)
	}
	return nil
}
