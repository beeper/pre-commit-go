// Command bridgelint checks mautrix bridgev2 bridges for the error-reporting and reliability
// mistakes found in Beeper's bridge audits. See README.md for the rules.
//
// It runs as a go vet tool: `bridgelint ./...` invokes `go vet -vettool=<itself> -json`, which analyses
// one package per process in dependency order and passes facts between them through files, then
// filters and prints the results. The go build cache keeps each package's results between runs.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis/unitchecker"

	"github.com/beeper/pre-commit-go/bridgelint/rules"
)

const (
	colorBold   = "\033[1m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorReset  = "\033[0m"
)

const (
	envConfig         = "BRIDGELINT_CONFIG"
	envMautrixVersion = "BRIDGELINT_MAUTRIX_VERSION"
)

var (
	outerFlags    = flag.NewFlagSet("bridgelint", flag.ExitOnError)
	verbose       = outerFlags.Bool("verbose", false, "also show info-level findings")
	configPath    = outerFlags.String("config", "", "path to .bridgelint.yaml (default: nearest one above each package)")
	baselinePath  = outerFlags.String("baseline", "", "ignore findings recorded in this baseline file")
	writeBaseline = outerFlags.Bool("write-baseline", false, "write all current findings to the -baseline file and exit 0")
	applyFixes    = outerFlags.Bool("fix", false, "apply suggested fixes for reported findings")
	includeTests  = outerFlags.Bool("tests", false, "also report findings in _test.go files")
	noColor       = outerFlags.Bool("no-color", os.Getenv("NO_COLOR") != "", "disable colored output")
	listRules     = outerFlags.Bool("rules", false, "list rules and exit")
)

type textEdit struct {
	Filename string `json:"filename"`
	Start    int    `json:"start"`
	End      int    `json:"end"`
	New      string `json:"new"`
}

type suggestedFix struct {
	Message string     `json:"message"`
	Edits   []textEdit `json:"edits"`
}

type jsonDiagnostic struct {
	Category       string         `json:"category"`
	Posn           string         `json:"posn"`
	Message        string         `json:"message"`
	SuggestedFixes []suggestedFix `json:"suggested_fixes"`
}

type finding struct {
	rule     string
	severity rules.Severity
	pos      token.Position
	message  string
	snippet  string
	fixes    []suggestedFix
}

func main() {
	if isVetTool(os.Args[1:]) {
		rules.ConfigOverride = os.Getenv(envConfig)
		rules.MautrixVersion = os.Getenv(envMautrixVersion)
		unitchecker.Main(rules.Analyzers...)
		return
	}
	outerFlags.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: bridgelint [flags] [packages]\n\nPackages default to ./...\n\n")
		outerFlags.PrintDefaults()
	}
	_ = outerFlags.Parse(os.Args[1:])
	if *listRules {
		printRules()
		return
	}
	patterns := outerFlags.Args()
	if len(patterns) == 0 {
		patterns = []string{"./..."}
	}
	os.Exit(run(patterns))
}

// isVetTool reports whether the go command is running us as a vet tool: it asks for the version and
// flags, then passes a single .cfg file per package.
func isVetTool(args []string) bool {
	if len(args) == 0 {
		return false
	}
	return args[0] == "-V=full" || args[0] == "-flags" || strings.HasSuffix(args[len(args)-1], ".cfg")
}

// mautrixVersion asks the go command which mautrix the current module builds against.
func mautrixVersion() string {
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Version}}|{{with .Replace}}{{.Version}}|{{.Path}}{{end}}", "maunium.net/go/mautrix").Output()
	if err != nil {
		return ""
	}
	parts := strings.Split(strings.TrimSpace(string(out)), "|")
	if len(parts) >= 3 && parts[2] != "" {
		if parts[1] == "" {
			return "local"
		}
		return parts[1]
	}
	return parts[0]
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
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "bridgelint: %v\n", err)
		return 2
	}
	configAbs := *configPath
	if configAbs != "" {
		if configAbs, err = filepath.Abs(configAbs); err != nil {
			fmt.Fprintf(os.Stderr, "bridgelint: %v\n", err)
			return 2
		}
	}
	cmd := exec.Command("go", append([]string{"vet", "-vettool=" + exe, "-json"}, patterns...)...)
	cmd.Env = append(os.Environ(), envConfig+"="+configAbs, envMautrixVersion+"="+mautrixVersion())
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	runErr := cmd.Run()
	findings, analysisErrs, err := parseVetJSON(&stdout)
	if err != nil || runErr != nil || len(analysisErrs) > 0 {
		os.Stderr.Write(stderr.Bytes())
		for _, e := range analysisErrs {
			fmt.Fprintf(os.Stderr, "bridgelint: %s\n", e)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "bridgelint: reading go vet output: %v\n", err)
		} else if runErr != nil {
			fmt.Fprintf(os.Stderr, "bridgelint: go vet: %v\n", runErr)
		}
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

// parseVetJSON reads go vet's -json output: a stream of objects mapping package ID to analyzer name to
// either a list of diagnostics or {"error": ...}. Test variants of a package report the same findings
// for its non-test files, so findings are deduplicated by position and message.
func parseVetJSON(r io.Reader) ([]finding, []string, error) {
	cwd, _ := os.Getwd()
	seen := map[string]bool{}
	var findings []finding
	var errs []string
	dec := json.NewDecoder(r)
	for {
		var tree map[string]map[string]json.RawMessage
		if err := dec.Decode(&tree); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, nil, err
		}
		for pkg, analyzers := range tree {
			for name, raw := range analyzers {
				var diags []jsonDiagnostic
				if err := json.Unmarshal(raw, &diags); err != nil {
					var e struct {
						Error string `json:"error"`
					}
					if json.Unmarshal(raw, &e) == nil && e.Error != "" {
						errs = append(errs, fmt.Sprintf("%s: %s: %s", pkg, name, e.Error))
						continue
					}
					return nil, nil, err
				}
				for _, d := range diags {
					pos := parsePosn(d.Posn)
					if !*includeTests && strings.HasSuffix(pos.Filename, "_test.go") {
						continue
					}
					key := fmt.Sprintf("%s:%d:%d:%s", pos.Filename, pos.Line, pos.Column, d.Message)
					if seen[key] {
						continue
					}
					seen[key] = true
					snippet := lineText(pos)
					if rel, err := filepath.Rel(cwd, pos.Filename); err == nil && !strings.HasPrefix(rel, "..") {
						pos.Filename = rel
					}
					id, sev := rules.SplitCategory(d.Category)
					findings = append(findings, finding{rule: id, severity: sev, pos: pos, message: d.Message, snippet: snippet, fixes: d.SuggestedFixes})
				}
			}
		}
	}
	return findings, errs, nil
}

// parsePosn parses "file:line:col".
func parsePosn(s string) token.Position {
	var pos token.Position
	rest := s
	if i := strings.LastIndexByte(rest, ':'); i >= 0 {
		pos.Column, _ = strconv.Atoi(rest[i+1:])
		rest = rest[:i]
	}
	if i := strings.LastIndexByte(rest, ':'); i >= 0 {
		pos.Line, _ = strconv.Atoi(rest[i+1:])
		rest = rest[:i]
	}
	pos.Filename = rest
	return pos
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

// fix applies the first suggested fix of each finding. A fix is applied whole or not at all: if any of
// its edits overlaps an edit already applied, it's skipped.
func fix(findings []finding) error {
	type span struct{ start, end int }
	byFile := map[string][]textEdit{}
	taken := map[string][]span{}
	overlaps := func(e textEdit) bool {
		for _, s := range taken[e.Filename] {
			if e.Start < s.end && s.start < e.End || e.Start == s.start {
				return true
			}
		}
		return false
	}
	for _, f := range findings {
		if len(f.fixes) == 0 {
			continue
		}
		edits := f.fixes[0].Edits
		ok := true
		for _, e := range edits {
			if overlaps(e) {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		for _, e := range edits {
			taken[e.Filename] = append(taken[e.Filename], span{e.Start, e.End})
			byFile[e.Filename] = append(byFile[e.Filename], e)
		}
	}
	for name, edits := range byFile {
		data, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		sort.Slice(edits, func(i, j int) bool { return edits[i].Start > edits[j].Start })
		for _, e := range edits {
			data = append(data[:e.Start:e.Start], append([]byte(e.New), data[e.End:]...)...)
		}
		if err := os.WriteFile(name, data, 0o644); err != nil {
			return err
		}
		fmt.Printf("bridgelint: applied %d edits to %s\n", len(edits), name)
	}
	return nil
}
