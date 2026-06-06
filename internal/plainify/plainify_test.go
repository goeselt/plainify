package plainify_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/goeselt/plainify/internal/plainify"
)

// writeFile is a test helper that writes content to a temp file and returns its path.
func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writeFile: %v", err)
	}
	return path
}

func TestScanFile_CRLFDetect(t *testing.T) {
	t.Parallel()
	path := writeFile(t, "file.txt", "line1\r\nline2\r\n")
	findings, err := plainify.ScanFile(path, "file.txt", plainify.Config{Fix: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected CRLF finding, got none")
	}
	if findings[0].Message == "" || findings[0].File != "file.txt" {
		t.Errorf("unexpected finding: %+v", findings[0])
	}
}

func TestScanFile_CRLFFix(t *testing.T) {
	t.Parallel()
	path := writeFile(t, "file.txt", "line1\r\nline2\r\n")
	findings, err := plainify.ScanFile(path, "file.txt", plainify.Config{Fix: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no remaining findings after fix, got %d: %v", len(findings), findings)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "line1\nline2\n" {
		t.Errorf("file not fixed: %q", got)
	}
}

func TestScanFile_SmartQuotesDetect(t *testing.T) {
	t.Parallel()
	path := writeFile(t, "file.txt", "He said \u201Chello\u201D and left.")
	findings, err := plainify.ScanFile(path, "file.txt", plainify.Config{Fix: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected smart-quote finding, got none")
	}
}

func TestScanFile_SmartQuotesFix(t *testing.T) {
	t.Parallel()
	path := writeFile(t, "file.txt", "He said \u201Chello\u201D.")
	findings, err := plainify.ScanFile(path, "file.txt", plainify.Config{Fix: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no remaining findings, got: %v", findings)
	}
	got, _ := os.ReadFile(path)
	if string(got) != `He said "hello".` {
		t.Errorf("smart quotes not replaced: %q", got)
	}
}

func TestScanFile_UTF8BOM(t *testing.T) {
	t.Parallel()
	path := writeFile(t, "file.txt", "\xEF\xBB\xBFhello")
	findings, err := plainify.ScanFile(path, "file.txt", plainify.Config{Fix: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected UTF-8 BOM finding, got none")
	}
	// AllowUtf8Bom suppresses the finding.
	findings, err = plainify.ScanFile(path, "file.txt", plainify.Config{AllowUtf8Bom: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings with AllowUtf8Bom=true, got: %v", findings)
	}
}

func TestScanFile_Binary(t *testing.T) {
	t.Parallel()
	path := writeFile(t, "file.bin", "hello\x00world")
	findings, err := plainify.ScanFile(path, "file.bin", plainify.Config{Fix: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected binary to be skipped, got findings: %v", findings)
	}
}

func TestScanFile_SkipExtension(t *testing.T) {
	t.Parallel()
	path := writeFile(t, "image.png", "not really a png but has non-ASCII \xFF")
	findings, err := plainify.ScanFile(path, "image.png", plainify.Config{Fix: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected skip extension, got findings: %v", findings)
	}
}

func TestScanFile_EmojiInMarkdown(t *testing.T) {
	t.Parallel()
	path := writeFile(t, "README.md", "# Hello \U0001F680 World\n")
	findings, err := plainify.ScanFile(path, "README.md", plainify.Config{Fix: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected emoji finding in markdown, got none")
	}
	if findings[0].Message != "emoji - use :rocket:" {
		t.Errorf("unexpected message: %q", findings[0].Message)
	}
}

func TestScanFile_EmojiInMarkdownFix(t *testing.T) {
	t.Parallel()
	path := writeFile(t, "README.md", "Deploy \U0001F680 now\n")
	findings, err := plainify.ScanFile(path, "README.md", plainify.Config{Fix: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings after fix, got: %v", findings)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "Deploy :rocket: now\n" {
		t.Errorf("emoji not replaced: %q", got)
	}
}

func TestScanFile_EmojiNotInNonMarkdown(t *testing.T) {
	t.Parallel()
	// Emoji in a .txt file should be reported as non-ASCII, not as emoji shortcode.
	path := writeFile(t, "notes.txt", "Launch \U0001F680\n")
	findings, err := plainify.ScanFile(path, "notes.txt", plainify.Config{Fix: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Message == "emoji \u2014 use :rocket:" {
			t.Errorf("expected non-ASCII finding, not emoji shortcode suggestion")
		}
	}
}

func TestScanFile_ZeroWidthDetect(t *testing.T) {
	t.Parallel()
	// Zero-width space (U+200B) between words -- invisible in editors.
	path := writeFile(t, "file.txt", "hello\u200Bworld")
	findings, err := plainify.ScanFile(path, "file.txt", plainify.Config{Fix: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected zero-width finding, got none")
	}
	if findings[0].Message != "zero-width character U+200B (zero-width space) - remove" {
		t.Errorf("unexpected message: %q", findings[0].Message)
	}
}

func TestScanFile_ZeroWidthFix(t *testing.T) {
	t.Parallel()
	path := writeFile(t, "file.txt", "hello\u200Bworld")
	findings, err := plainify.ScanFile(path, "file.txt", plainify.Config{Fix: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no remaining findings after fix, got: %v", findings)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "helloworld" {
		t.Errorf("zero-width char not removed: %q", got)
	}
}

func TestScanFile_FixPreservesPermissions(t *testing.T) {
	t.Parallel()
	path := writeFile(t, "script.sh", "echo \u201Chello\u201D\n")
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := plainify.ScanFile(path, "script.sh", plainify.Config{Fix: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o755 {
		t.Errorf("permissions changed: got %o, want 755", fi.Mode().Perm())
	}
}

func TestScanFile_BidiDetect(t *testing.T) {
	t.Parallel()
	// Right-to-left override (U+202E) -- Trojan Source attack vector.
	path := writeFile(t, "file.go", "var x = \u202E\"secret\"")
	findings, err := plainify.ScanFile(path, "file.go", plainify.Config{Fix: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected bidi finding, got none")
	}
	want := "bidirectional control character U+202E (right-to-left override) - remove (Trojan Source risk)"
	if findings[0].Message != want {
		t.Errorf("unexpected message: %q", findings[0].Message)
	}
}

func TestScanFile_BidiFix(t *testing.T) {
	t.Parallel()
	path := writeFile(t, "file.go", "var x = \u202E\"secret\"")
	findings, err := plainify.ScanFile(path, "file.go", plainify.Config{Fix: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no remaining findings after fix, got: %v", findings)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "var x = \"secret\"" {
		t.Errorf("bidi char not removed: %q", got)
	}
}

func TestScanFile_NoDoubleReport(t *testing.T) {
	t.Parallel()
	// A typographic character must not be reported by both findReplacements
	// and findNonASCII on the same line.
	path := writeFile(t, "file.txt", "it\u2019s fine") // right single quotation mark
	findings, err := plainify.ScanFile(path, "file.txt", plainify.Config{Fix: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Exactly one finding expected -- the typographic char report only.
	if len(findings) != 1 {
		t.Errorf("expected 1 finding (no double-report), got %d: %v", len(findings), findings)
	}
}

func TestReplaceEmoji(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
	}{
		{"hello", "hello"},
		{"\U0001F680", ":rocket:"},
		{"fix \U0001F41B and \u2728", "fix :bug: and :sparkles:"},
		{"\u2764\uFE0F you", ":heart: you"},
	}
	for _, tc := range cases {
		got := plainify.ReplaceEmoji(tc.in)
		if got != tc.want {
			t.Errorf("ReplaceEmoji(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestScanFile_UTF8BOMAutoFix(t *testing.T) {
	t.Parallel()
	path := writeFile(t, "file.txt", "\xEF\xBB\xBFhello world\n")
	findings, err := plainify.ScanFile(path, "file.txt", plainify.Config{Fix: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings after BOM fix, got: %v", findings)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "hello world\n" {
		t.Errorf("BOM not removed: %q", got)
	}
}

func TestScanFile_UTF8BOMAllowed(t *testing.T) {
	t.Parallel()
	path := writeFile(t, "file.txt", "\xEF\xBB\xBFhello\n")
	findings, err := plainify.ScanFile(path, "file.txt", plainify.Config{Fix: true, AllowUtf8Bom: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings with AllowUtf8Bom, got: %v", findings)
	}
	// BOM should be preserved when allowed.
	got, _ := os.ReadFile(path)
	if string(got) != "\xEF\xBB\xBFhello\n" {
		t.Errorf("BOM should be preserved when allowed: %q", got)
	}
}

func TestScanFile_UTF8BOMAllowedPreservedWhenFixingOtherIssue(t *testing.T) {
	t.Parallel()
	path := writeFile(t, "file.txt", "\xEF\xBB\xBFline1\r\nline2\r\n")
	findings, err := plainify.ScanFile(path, "file.txt", plainify.Config{Fix: true, AllowUtf8Bom: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings with AllowUtf8Bom, got: %v", findings)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "\xEF\xBB\xBFline1\nline2\n" {
		t.Errorf("BOM should be preserved while fixing CRLF: %q", got)
	}
}

func TestScanFile_InvalidUTF8NotRewrittenInFixMode(t *testing.T) {
	t.Parallel()
	original := []byte{'o', 'k', 0xFF, '\r', '\n'}
	path := filepath.Join(t.TempDir(), "file.txt")
	if err := os.WriteFile(path, original, 0o644); err != nil {
		t.Fatal(err)
	}

	findings, err := plainify.ScanFile(path, "file.txt", plainify.Config{Fix: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one invalid UTF-8 finding, got %d: %v", len(findings), findings)
	}
	if findings[0].Message != "invalid UTF-8 byte 0xFF - convert to UTF-8" {
		t.Errorf("unexpected finding: %+v", findings[0])
	}
	got, _ := os.ReadFile(path)
	if string(got) != string(original) {
		t.Errorf("invalid UTF-8 file should not be rewritten: got %v, want %v", got, original)
	}
}

func TestScanFile_StrayControlDetect(t *testing.T) {
	t.Parallel()
	// Form feed (0x0C) in the middle of a file.
	path := writeFile(t, "file.txt", "page1\x0Cpage2\n")
	findings, err := plainify.ScanFile(path, "file.txt", plainify.Config{Fix: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected stray control finding, got none")
	}
	if findings[0].Message != "stray control character 0x0C (FF) - remove" {
		t.Errorf("unexpected message: %q", findings[0].Message)
	}
}

func TestScanFile_StrayControlFix(t *testing.T) {
	t.Parallel()
	// Vertical tab (0x0B) and form feed (0x0C).
	path := writeFile(t, "file.txt", "hello\x0Bworld\x0C\n")
	findings, err := plainify.ScanFile(path, "file.txt", plainify.Config{Fix: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings after fix, got: %v", findings)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "helloworld\n" {
		t.Errorf("stray controls not removed: %q", got)
	}
}

func TestScanFile_StrayControlTabPreserved(t *testing.T) {
	t.Parallel()
	// Tabs must not be removed.
	path := writeFile(t, "file.go", "func main() {\n\tfmt.Println()\n}\n")
	findings, err := plainify.ScanFile(path, "file.go", plainify.Config{Fix: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Message == "stray control character 0x09 (HT) - remove" {
			t.Error("tab should not be flagged as stray control")
		}
	}
}

func TestScanFile_MixedLineEndings(t *testing.T) {
	t.Parallel()
	// Mix of CRLF and LF in the same file.
	path := writeFile(t, "file.txt", "line1\r\nline2\nline3\r\n")
	findings, err := plainify.ScanFile(path, "file.txt", plainify.Config{Fix: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected mixed line endings finding, got none")
	}
	if findings[0].Message != "mixed line endings (CRLF and LF) - convert to LF" {
		t.Errorf("unexpected message: %q", findings[0].Message)
	}
}

func TestScanFile_PureCRLF(t *testing.T) {
	t.Parallel()
	// Pure CRLF (no mixed) should still report the standard CRLF message.
	path := writeFile(t, "file.txt", "line1\r\nline2\r\n")
	findings, err := plainify.ScanFile(path, "file.txt", plainify.Config{Fix: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected CRLF finding, got none")
	}
	if findings[0].Message != "CRLF line endings - convert to LF" {
		t.Errorf("unexpected message: %q", findings[0].Message)
	}
}

func TestScanFile_BELControlFix(t *testing.T) {
	t.Parallel()
	// BEL character (0x07) -- sometimes left in from terminal escape sequences.
	path := writeFile(t, "file.txt", "alert\x07done\n")
	findings, err := plainify.ScanFile(path, "file.txt", plainify.Config{Fix: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings after fix, got: %v", findings)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "alertdone\n" {
		t.Errorf("BEL not removed: %q", got)
	}
}
