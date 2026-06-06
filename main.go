// plainify detects and fixes encoding issues, CRLF line endings, non-ASCII
// typographic characters, and emoji in text files.
//
// Usage:
//
//	plainify [options] [path...]
//
// With no paths, files are discovered via git ls-files in the workspace.
// Output: JSON result on stdout, human-readable progress on stderr.
// Exit codes: 0 = clean, 1 = findings, 2 = error.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/goeselt/plainify/internal/plainify"
)

// version is set at build time via -ldflags "-X main.version=v1.2.3".
var version = "dev"

type multiFlag []string

func (f *multiFlag) String() string     { return strings.Join(*f, ",") }
func (f *multiFlag) Set(v string) error { *f = append(*f, v); return nil }

type output struct {
	Status   string             `json:"status"`
	Count    int                `json:"findings_count"`
	Findings []plainify.Finding `json:"findings"`
}

func main() {
	nofix := flag.Bool("nofix", false, "report issues without modifying files")
	flag.BoolVar(nofix, "n", false, "shorthand for --nofix")
	workspace := flag.String("workspace", "", "repository root for git discovery and relative paths (default: first directory arg or cwd)")
	allowUtf8Bom := flag.Bool("allow-utf8-bom", false, "do not flag UTF-8 BOM")
	quiet := flag.Bool("q", false, "suppress human-readable progress output")
	showVersion := flag.Bool("version", false, "print version and exit")
	var excludes multiFlag
	flag.Var(&excludes, "exclude", "exclude files matching `regex` (repeatable)")

	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	ws, files := resolveWorkspaceAndFiles(*workspace, flag.Args())

	absWS, err := filepath.Abs(ws)
	if err != nil {
		fatal("workspace: %v", err)
	}

	if len(files) == 0 {
		files, err = discoverFiles(absWS)
		if err != nil {
			fatal("file discovery: %v", err)
		}
	}

	excludeREs, err := compileExcludes(excludes)
	if err != nil {
		fatal("%v", err)
	}

	cfg := plainify.Config{Fix: !*nofix, AllowUtf8Bom: *allowUtf8Bom}

	if !*quiet {
		fmt.Fprintf(os.Stderr, "[plainify] checking %d file(s)...\n", len(files))
	}

	var allFindings []plainify.Finding
	hadScanError := false
	for _, f := range files {
		absPath := f
		if !filepath.IsAbs(f) {
			absPath = filepath.Join(absWS, f)
		}
		relPath := toSlash(relativize(absWS, absPath))

		if excluded(relPath, excludeREs) {
			continue
		}

		findings, err := plainify.ScanFile(absPath, relPath, cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[plainify] warning: %v\n", err)
			hadScanError = true
			continue
		}
		allFindings = append(allFindings, findings...)
	}

	status := "pass"
	if hadScanError {
		status = "error"
	} else if len(allFindings) > 0 {
		status = "fail"
	}

	if !*quiet {
		switch status {
		case "error":
			fmt.Fprintln(os.Stderr, "[plainify] error: one or more files could not be scanned")
		case "pass":
			fmt.Fprintln(os.Stderr, "[plainify] pass")
		default:
			fmt.Fprintf(os.Stderr, "[plainify] %d finding(s)\n", len(allFindings))
			for _, f := range allFindings {
				printFinding(f)
			}
		}
	}

	out := output{
		Status:   status,
		Count:    len(allFindings),
		Findings: allFindings,
	}
	if out.Findings == nil {
		out.Findings = []plainify.Finding{}
	}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		fatal("encode output: %v", err)
	}

	if hadScanError {
		os.Exit(2)
	}
	if len(allFindings) > 0 {
		os.Exit(1)
	}
}

// resolveWorkspaceAndFiles separates the workspace directory from explicit file paths.
func resolveWorkspaceAndFiles(wsFlag string, args []string) (ws string, files []string) {
	ws = wsFlag
	for _, a := range args {
		fi, err := os.Stat(a)
		if err == nil && fi.IsDir() {
			if ws == "" {
				ws = a
			}
		} else {
			files = append(files, a)
		}
	}
	if ws == "" {
		var err error
		ws, err = os.Getwd()
		if err != nil {
			fatal("getwd: %v", err)
		}
	}
	return ws, files
}

// discoverFiles runs git ls-files to find tracked and untracked (non-ignored) files.
func discoverFiles(workspace string) ([]string, error) {
	cmd := exec.Command("git", "ls-files", "--cached", "--others", "--exclude-standard")
	cmd.Dir = workspace
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-files: %w", err)
	}
	seen := make(map[string]bool)
	var files []string
	for _, line := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		if line == "" || seen[line] {
			continue
		}
		seen[line] = true
		files = append(files, filepath.Join(workspace, filepath.FromSlash(line)))
	}
	return files, nil
}

func compileExcludes(patterns []string) ([]*regexp.Regexp, error) {
	res := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("invalid --exclude pattern %q: %w", p, err)
		}
		res = append(res, re)
	}
	return res, nil
}

func excluded(relPath string, res []*regexp.Regexp) bool {
	for _, re := range res {
		if re.MatchString(relPath) {
			return true
		}
	}
	return false
}

func relativize(workspace, path string) string {
	rel, err := filepath.Rel(workspace, path)
	if err != nil {
		return path
	}
	return rel
}

func toSlash(p string) string { return filepath.ToSlash(p) }

func printFinding(f plainify.Finding) {
	var sb strings.Builder
	sb.WriteString("  ")
	sb.WriteString(f.File)
	if f.Line > 0 {
		fmt.Fprintf(&sb, ":%d", f.Line)
		if f.Col > 0 {
			fmt.Fprintf(&sb, ":%d", f.Col)
		}
	}
	sb.WriteString(" ")
	sb.WriteString(f.Message)
	fmt.Fprintln(os.Stderr, sb.String())
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[plainify] error: "+format+"\n", args...)
	os.Exit(2)
}
