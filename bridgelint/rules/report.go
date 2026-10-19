package rules

import (
	"fmt"
	"go/ast"
	"go/token"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"golang.org/x/tools/go/analysis"
)

type Severity string

const (
	SeverityError   Severity = "error"
	SeverityWarning Severity = "warning"
	SeverityInfo    Severity = "info"
)

func ParseSeverity(s string) (Severity, bool) {
	switch Severity(s) {
	case SeverityError, SeverityWarning, SeverityInfo:
		return Severity(s), true
	}
	return "", false
}

type Rule struct {
	ID       string
	Severity Severity
	Title    string
}

var Rules = map[string]Rule{}

func rule(id string, sev Severity, title string) string {
	Rules[id] = Rule{ID: id, Severity: sev, Title: title}
	return id
}

var (
	BL000 = rule("BL000", SeverityError, "bridgelint:ignore without a reason")

	MSS001 = rule("MSS001", SeverityError, "bare error returned from a Matrix handler")
	MSS002 = rule("MSS002", SeverityError, "permanent rejection left retriable")
	MSS003 = rule("MSS003", SeverityWarning, "raw error text shown to the user")
	MSS004 = rule("MSS004", SeverityWarning, "certainty that doesn't match the code path")
	MSS005 = rule("MSS005", SeverityInfo, "reason missing on a classified failure")
	MSS006 = rule("MSS006", SeverityWarning, "the bridge has an error classifier but the handler doesn't use it")

	BS001 = rule("BS001", SeverityInfo, "explicit RELOGIN is redundant")
	BS002 = rule("BS002", SeverityError, "restriction or ban sent with the wrong state or action")
	BS003 = rule("BS003", SeverityError, "raw error text in bridge state Message")
	BS004 = rule("BS004", SeverityError, "error state without a stable code")
	BS005 = rule("BS005", SeverityWarning, "bridge state code without a human message")
	BS006 = rule("BS006", SeverityWarning, "UNKNOWN_ERROR for a classifiable failure")
	BS007 = rule("BS007", SeverityError, "TRANSIENT_DISCONNECT with no retry")
	BS009 = rule("BS009", SeverityWarning, "library disconnect events not handled")
	BS010 = rule("BS010", SeverityWarning, "TRANSIENT_DISCONNECT for a permanent condition")
	BS011 = rule("BS011", SeverityWarning, "every connect error treated as BAD_CREDENTIALS")

	LP001 = rule("LP001", SeverityError, "plain error from login or provisioning")
	LP002 = rule("LP002", SeverityError, "rate limit not returned as 429")
	LP003 = rule("LP003", SeverityWarning, "upstream outage returned as 4xx")
	LP004 = rule("LP004", SeverityWarning, "network status passed through as HTTP status")
	LP005 = rule("LP005", SeverityWarning, "RespError without a status code")
	LP006 = rule("LP006", SeverityError, "error swallowed and success returned")
	LP007 = rule("LP007", SeverityInfo, "RespError struct literal for a standard Matrix error code")
	LP008 = rule("LP008", SeverityInfo, "connector re-validates input the login step already describes")

	EP001 = rule("EP001", SeverityError, "matching errors by string")
	EP002 = rule("EP002", SeverityWarning, "library error without a typed status")
	EP003 = rule("EP003", SeverityInfo, "errors.Join in a user-facing path")

	GR001 = rule("GR001", SeverityWarning, "response body not closed")
	GR002 = rule("GR002", SeverityWarning, "HTTP request without context or timeout")
	GR003 = rule("GR003", SeverityWarning, "retry resends a consumed request body")
	GR004 = rule("GR004", SeverityError, "process exit or panic in connector or library code")
	GR007 = rule("GR007", SeverityWarning, "blocking channel send in a Matrix handler")
	GR008 = rule("GR008", SeverityWarning, "sync cursor saved before queued events are handled")
	GR009 = rule("GR009", SeverityWarning, "package-level map or slice written at runtime, shared across logins")
	GR011 = rule("GR011", SeverityWarning, "RoomFeatures.ID is constant while capabilities vary")
	GR013 = rule("GR013", SeverityWarning, "LogoutRemote doesn't stop the client")
)

// Category is "<rule>:<severity>" so drivers can recover both from a Diagnostic.
func Category(id string, sev Severity) string {
	return id + ":" + string(sev)
}

func SplitCategory(cat string) (id string, sev Severity) {
	id, s, _ := strings.Cut(cat, ":")
	return id, Severity(s)
}

var ignoreRegex = regexp.MustCompile(`^//\s*bridgelint:ignore\b(.*)$`)

type ignoreEntry struct {
	rules  map[string]struct{}
	reason string
}

type passState struct {
	cfg     *Config
	ignores map[string]map[int]*ignoreEntry
}

var passStates sync.Map // *analysis.Pass -> *passState

func stateFor(pass *analysis.Pass) *passState {
	if st, ok := passStates.Load(pass); ok {
		return st.(*passState)
	}
	st := &passState{ignores: map[string]map[int]*ignoreEntry{}}
	var dir string
	for _, f := range pass.Files {
		name := pass.Fset.File(f.Pos()).Name()
		if dir == "" {
			dir = filepath.Dir(name)
		}
		lines := map[int]*ignoreEntry{}
		for _, cg := range f.Comments {
			for _, c := range cg.List {
				m := ignoreRegex.FindStringSubmatch(c.Text)
				if m == nil {
					continue
				}
				fields := strings.Fields(m[1])
				entry := &ignoreEntry{rules: map[string]struct{}{}}
				for i, field := range fields {
					if _, ok := Rules[field]; ok || field == "all" {
						entry.rules[field] = struct{}{}
						continue
					}
					entry.reason = strings.Join(fields[i:], " ")
					break
				}
				lines[pass.Fset.Position(c.Pos()).Line] = entry
			}
		}
		st.ignores[name] = lines
	}
	st.cfg = LoadConfig(dir)
	actual, _ := passStates.LoadOrStore(pass, st)
	return actual.(*passState)
}

func (st *passState) ignored(pos token.Position, id string) bool {
	lines := st.ignores[pos.Filename]
	for _, line := range []int{pos.Line, pos.Line - 1} {
		entry := lines[line]
		if entry == nil || entry.reason == "" {
			continue
		}
		if _, ok := entry.rules[id]; ok {
			return true
		}
		if _, ok := entry.rules["all"]; ok {
			return true
		}
	}
	return false
}

// ConfigFor returns the .bridgelint.yaml that applies to the package being analysed.
func ConfigFor(pass *analysis.Pass) *Config {
	return stateFor(pass).cfg
}

type reportOpt func(*analysis.Diagnostic, *Severity)

func withSeverity(sev Severity) reportOpt {
	return func(_ *analysis.Diagnostic, s *Severity) { *s = sev }
}

func withFix(msg string, edits ...analysis.TextEdit) reportOpt {
	return func(d *analysis.Diagnostic, _ *Severity) {
		d.SuggestedFixes = append(d.SuggestedFixes, analysis.SuggestedFix{Message: msg, TextEdits: edits})
	}
}

func report(pass *analysis.Pass, node ast.Node, id string, msg string, opts ...reportOpt) {
	reportRange(pass, node.Pos(), node.End(), id, msg, opts...)
}

func reportRange(pass *analysis.Pass, pos, end token.Pos, id string, msg string, opts ...reportOpt) {
	st := stateFor(pass)
	if st.cfg.disabled(id) {
		return
	}
	position := pass.Fset.Position(pos)
	if st.ignored(position, id) {
		return
	}
	sev := Rules[id].Severity
	d := analysis.Diagnostic{Pos: pos, End: end}
	for _, opt := range opts {
		opt(&d, &sev)
	}
	if override, ok := st.cfg.Severity[id]; ok {
		if s, ok := ParseSeverity(override); ok {
			sev = s
		}
	}
	d.Category = Category(id, sev)
	d.Message = fmt.Sprintf("%s: %s", id, msg)
	pass.Report(d)
}

func checkIgnores(pass *analysis.Pass) {
	st := stateFor(pass)
	for _, f := range pass.Files {
		for _, cg := range f.Comments {
			for _, c := range cg.List {
				m := ignoreRegex.FindStringSubmatch(c.Text)
				if m == nil {
					continue
				}
				entry := st.ignores[pass.Fset.Position(c.Pos()).Filename][pass.Fset.Position(c.Pos()).Line]
				if entry == nil {
					continue
				}
				if len(entry.rules) == 0 {
					report(pass, c, BL000, "bridgelint:ignore must name the rules it suppresses, then a reason")
				} else if entry.reason == "" {
					report(pass, c, BL000, "bridgelint:ignore needs a reason after the rule IDs")
				}
			}
		}
	}
}
