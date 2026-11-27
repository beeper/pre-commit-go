package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const testFile = `package sub

import (
	"time"

	"example.com/m/other"
	"example.com/m/missing"
)

type Count int64
type Alias = Count

type S struct {
	A Alias         ` + "`json:\"a,omitempty\"`" + `
	B time.Duration ` + "`json:\"b,omitempty\"`" + `
	C other.Flag    ` + "`json:\"c,omitempty\"`" + `
	D string        ` + "`json:\"d,omitempty\"`" + `
	E missing.Type  ` + "`json:\"e,omitempty\"`" + `
	F *int          ` + "`json:\"f,omitempty\"`" + `
}
`

func writeModule(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"go.mod":     "module example.com/m\n\ngo 1.24\n",
		"other/o.go": "package other\n\ntype Flag bool\n",
		"sub/a.go":   testFile,
	}
	for name, contents := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(dir, "sub", "a.go")
}

func runOn(t *testing.T, file string) map[string]bool {
	t.Helper()
	if !processFile(file, loadTypedFields([]string{file})) {
		t.Fatal("expected changes")
	}
	contents, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	fixed := make(map[string]bool)
	for _, field := range []string{"a", "b", "c", "d", "e", "f"} {
		fixed[field] = strings.Contains(string(contents), `json:"`+field+`,omitzero"`)
	}
	return fixed
}

func TestTyped(t *testing.T) {
	fixed := runOn(t, writeModule(t))
	want := map[string]bool{"a": true, "b": true, "c": true, "d": false, "e": false, "f": false}
	for field, w := range want {
		if fixed[field] != w {
			t.Errorf("field %s: fixed=%v, want %v", field, fixed[field], w)
		}
	}
}

// A hook binary built with an older Go than the go command (or a go command that refuses to run)
// must not fail; it falls back to the syntactic check.
func TestGoCommandFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a shell script as the fake go command")
	}
	file := writeModule(t)
	bin := t.TempDir()
	err := os.WriteFile(filepath.Join(bin, "go"), []byte("#!/bin/sh\necho 'go: broken toolchain' >&2\nexit 1\n"), 0o755)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	fixed := runOn(t, file)
	want := map[string]bool{"a": true, "b": false, "c": false, "d": false, "e": false, "f": false}
	for field, w := range want {
		if fixed[field] != w {
			t.Errorf("field %s: fixed=%v, want %v", field, fixed[field], w)
		}
	}
}
