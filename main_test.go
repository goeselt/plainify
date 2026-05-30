package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestDiscoverFiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// Initialize a git repo with one tracked file.
	run(t, dir, "git", "init")
	run(t, dir, "git", "config", "user.email", "test@test.local")
	run(t, dir, "git", "config", "user.name", "Test")
	writeTestFile(t, filepath.Join(dir, "hello.txt"), "hello\n")
	run(t, dir, "git", "add", "hello.txt")
	run(t, dir, "git", "commit", "-m", "init")

	// Add an untracked (non-ignored) file.
	writeTestFile(t, filepath.Join(dir, "untracked.txt"), "world\n")

	files, err := discoverFiles(dir)
	if err != nil {
		t.Fatalf("discoverFiles: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("expected 2 files, got %d: %v", len(files), files)
	}
}

func TestCompileExcludes(t *testing.T) {
	t.Parallel()
	res, err := compileExcludes([]string{`vendor`, `\.pb\.go$`})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res) != 2 {
		t.Fatalf("expected 2 regexps, got %d", len(res))
	}
}

func TestCompileExcludes_Invalid(t *testing.T) {
	t.Parallel()
	_, err := compileExcludes([]string{`[invalid`})
	if err == nil {
		t.Fatal("expected error for invalid regex")
	}
}

func TestExcluded(t *testing.T) {
	t.Parallel()
	res, _ := compileExcludes([]string{`vendor/`, `\.gen\.go$`})
	tests := []struct {
		path string
		want bool
	}{
		{"vendor/lib/foo.go", true},
		{"src/main.go", false},
		{"src/types.gen.go", true},
	}
	for _, tc := range tests {
		got := excluded(tc.path, res)
		if got != tc.want {
			t.Errorf("excluded(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestResolveWorkspaceAndFiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	file := filepath.Join(dir, "a.txt")
	writeTestFile(t, file, "x")

	ws, files := resolveWorkspaceAndFiles("", []string{dir, file})
	if ws != dir {
		t.Errorf("workspace = %q, want %q", ws, dir)
	}
	if len(files) != 1 || files[0] != file {
		t.Errorf("files = %v, want [%s]", files, file)
	}
}

func TestIntegration_CLINofix(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// Initialize a git repo with a file containing CRLF.
	run(t, dir, "git", "init")
	run(t, dir, "git", "config", "user.email", "test@test.local")
	run(t, dir, "git", "config", "user.name", "Test")
	writeTestFile(t, filepath.Join(dir, "bad.txt"), "line1\r\nline2\r\n")
	run(t, dir, "git", "add", "bad.txt")
	run(t, dir, "git", "commit", "-m", "init")

	// Build the binary.
	bin := filepath.Join(t.TempDir(), "plainify")
	buildCmd := exec.Command("go", "build", "-o", bin, ".")
	buildCmd.Dir = testProjectRoot(t)
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	// Run in nofix mode.
	cmd := exec.Command(bin, "--nofix", "-q", dir)
	stdout, err := cmd.Output()
	if err == nil {
		t.Fatal("expected non-zero exit for findings")
	}

	var result output
	if err := json.Unmarshal(stdout, &result); err != nil {
		t.Fatalf("unmarshal: %v\nstdout: %s", err, stdout)
	}
	if result.Status != "fail" {
		t.Errorf("status = %q, want fail", result.Status)
	}
	if result.Count == 0 {
		t.Error("expected findings_count > 0")
	}
}

func TestIntegration_CLIFix(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// Initialize a git repo with a file containing smart quotes.
	run(t, dir, "git", "init")
	run(t, dir, "git", "config", "user.email", "test@test.local")
	run(t, dir, "git", "config", "user.name", "Test")
	writeTestFile(t, filepath.Join(dir, "doc.txt"), "He said \u201Chello\u201D.\n")
	run(t, dir, "git", "add", "doc.txt")
	run(t, dir, "git", "commit", "-m", "init")

	// Build the binary.
	bin := filepath.Join(t.TempDir(), "plainify")
	buildCmd := exec.Command("go", "build", "-o", bin, ".")
	buildCmd.Dir = testProjectRoot(t)
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	// Run in fix mode (default).
	cmd := exec.Command(bin, "-q", dir)
	stdout, err := cmd.Output()
	if err != nil {
		t.Fatalf("expected exit 0 after fix, got: %v\nstdout: %s", err, stdout)
	}

	var result output
	if err := json.Unmarshal(stdout, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if result.Status != "pass" {
		t.Errorf("status = %q, want pass", result.Status)
	}

	got, _ := os.ReadFile(filepath.Join(dir, "doc.txt"))
	if string(got) != "He said \"hello\".\n" {
		t.Errorf("file not fixed: %q", got)
	}
}

// helpers

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func run(t *testing.T, dir string, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
}

func testProjectRoot(t *testing.T) string {
	t.Helper()
	// Walk up from the test file to find go.mod.
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return dir
}
