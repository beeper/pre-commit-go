package main

import (
	"go/token"
	"path/filepath"
	"testing"
)

func TestBaselineFromSubdirectory(t *testing.T) {
	root := t.TempDir()
	baseline := filepath.Join(root, "bridgelint.baseline.json")
	file := filepath.Join(root, "pkg", "connector", "client.go")
	fromRoot := finding{rule: "MSS001", pos: token.Position{Filename: "pkg/connector/client.go", Line: 3}, file: file, snippet: "\treturn nil, err"}
	if err := saveBaseline(baseline, root, []finding{fromRoot}); err != nil {
		t.Fatal(err)
	}
	fromSubdir := fromRoot
	fromSubdir.pos.Filename = "connector/client.go"
	fromSubdir.pos.Line = 5
	left, err := filterBaseline(baseline, root, []finding{fromSubdir})
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Errorf("finding run from a subdirectory wasn't matched by the baseline: %+v", left)
	}
}
