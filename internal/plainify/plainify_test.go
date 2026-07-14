package plainify_test

import (
	"os"
	"path/filepath"
	"strings"
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
	// Exactly one finding: the BOM must not additionally be reported as a
	// non-ASCII or zero-width U+FEFF character.
	if len(findings) != 1 {
		t.Fatalf("expected exactly the BOM finding, got %d: %v", len(findings), findings)
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

func TestScanFile_EmojiAllowedInEveryFileType(t *testing.T) {
	t.Parallel()
	// Emoji are deliberate, visible content: never reported, never rewritten,
	// regardless of file type. Workflow step names, shell and Go output
	// strings, and documentation all use them legitimately.
	cases := []struct{ name, content string }{
		{"README.md", "# Hello \U0001F680 World\n"},
		{"rules.mdc", "Use \u2705 for pass and \u274C for fail\n"},
		{"ci.yml", "- name: Build \U0001F680\n  run: echo \"\u2705 done\"\n"},
		{"main.go", "func main() { println(\"\u2705 done\") }\n"},
		{"deploy.sh", "echo \"\U0001F680 deploying\"\n"},
		{"notes.txt", "Launch \U0001F680\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := writeFile(t, tc.name, tc.content)
			findings, err := plainify.ScanFile(path, tc.name, plainify.Config{Fix: false})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(findings) != 0 {
				t.Errorf("expected emoji to be allowed, got: %v", findings)
			}
			// Fix mode must leave the file byte-identical.
			if _, err := plainify.ScanFile(path, tc.name, plainify.Config{Fix: true}); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			got, _ := os.ReadFile(path)
			if string(got) != tc.content {
				t.Errorf("emoji must not be rewritten: %q", got)
			}
		})
	}
}

func TestScanFile_EmojiSequencesPreserved(t *testing.T) {
	t.Parallel()
	// Variation selector (red heart), ZWJ sequence (family), keycap, flag.
	// The invisible glue (U+200D, U+FE0F, U+20E3) must survive fix mode in a
	// non-Markdown file too, or a family emoji would be split into its parts.
	content := "\u2764\uFE0F \U0001F468\u200D\U0001F469\u200D\U0001F467 1\uFE0F\u20E3 \U0001F1E9\U0001F1EA\n"
	path := writeFile(t, "ci.yml", content)
	findings, err := plainify.ScanFile(path, "ci.yml", plainify.Config{Fix: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected emoji sequences to be allowed, got: %v", findings)
	}
	findings, err = plainify.ScanFile(path, "ci.yml", plainify.Config{Fix: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings in fix mode, got: %v", findings)
	}
	got, _ := os.ReadFile(path)
	if string(got) != content {
		t.Errorf("emoji sequences must not be modified: %q", got)
	}
}

func TestScanFile_ZWJOutsideEmojiStillRemoved(t *testing.T) {
	t.Parallel()
	// A zero-width joiner between letters is not an emoji sequence: allowing
	// emoji everywhere must not weaken the invisible-character check.
	path := writeFile(t, "doc.md", "hel\u200Dlo\n")
	findings, err := plainify.ScanFile(path, "doc.md", plainify.Config{Fix: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one zero-width finding, got %d: %v", len(findings), findings)
	}
	if findings[0].Message != "zero-width character U+200D (zero-width joiner) - remove" {
		t.Errorf("unexpected message: %q", findings[0].Message)
	}

	if _, err := plainify.ScanFile(path, "doc.md", plainify.Config{Fix: true}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "hello\n" {
		t.Errorf("ZWJ outside emoji not removed: %q", got)
	}
}

func TestScanFile_StrayVariationSelectorStillFlagged(t *testing.T) {
	t.Parallel()
	// A variation selector without a preceding emoji base is not emoji glue
	// and remains a finding.
	path := writeFile(t, "doc.md", "weird a\uFE0F here\n")
	findings, err := plainify.ScanFile(path, "doc.md", plainify.Config{Fix: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d: %v", len(findings), findings)
	}
	if findings[0].Message != "non-ASCII character U+FE0F" {
		t.Errorf("unexpected message: %q", findings[0].Message)
	}
}

func TestScanFile_NonASCIILetterStillReported(t *testing.T) {
	t.Parallel()
	// Accented letters can arrive by accident (encoding mishap, bad paste), so
	// unlike emoji they remain a backstop finding outside typographic fixes.
	path := writeFile(t, "main.go", "s := \"Gr\u00FC\u00DFe\"\n")
	findings, err := plainify.ScanFile(path, "main.go", plainify.Config{Fix: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d: %v", len(findings), findings)
	}
	if findings[0].Message != "non-ASCII character U+00FC" {
		t.Errorf("unexpected message: %q", findings[0].Message)
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

func TestScanFile_ColumnsCountRunes(t *testing.T) {
	t.Parallel()
	// An accented character (2 bytes in UTF-8) precedes the em-dash: the
	// reported column must be the rune position, not the byte offset.
	path := writeFile(t, "file.txt", "a\u00E9b\u2014x\n")
	findings, err := plainify.ScanFile(path, "file.txt", plainify.Config{Fix: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings, got none")
	}
	if findings[0].Col != 4 {
		t.Errorf("em-dash column = %d, want 4 (rune-based)", findings[0].Col)
	}
}

func TestScanFile_NullByteAfterHeaderIsBinary(t *testing.T) {
	t.Parallel()
	// A null byte beyond the 8 KB header must still mark the file as binary;
	// it must not be deleted as a stray control character in fix mode.
	content := strings.Repeat("a", 9000) + "\x00b\r\n"
	path := writeFile(t, "file.txt", content)
	findings, err := plainify.ScanFile(path, "file.txt", plainify.Config{Fix: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected binary to be skipped, got findings: %v", findings)
	}
	got, _ := os.ReadFile(path)
	if string(got) != content {
		t.Error("binary file must not be rewritten")
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

func TestScanFile_WordJoinerDetectAndFix(t *testing.T) {
	t.Parallel()
	path := writeFile(t, "file.txt", "a\u2060b\n")
	findings, err := plainify.ScanFile(path, "file.txt", plainify.Config{Fix: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d: %v", len(findings), findings)
	}
	if findings[0].Message != "zero-width character U+2060 (word joiner) - remove" {
		t.Errorf("unexpected message: %q", findings[0].Message)
	}

	if _, err := plainify.ScanFile(path, "file.txt", plainify.Config{Fix: true}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "ab\n" {
		t.Errorf("word joiner not removed: %q", got)
	}
}

func TestScanFile_TagCharactersRemoved(t *testing.T) {
	t.Parallel()
	// Unicode tag characters (U+E0000-U+E007F) are a data-smuggling channel.
	path := writeFile(t, "file.txt", "hi\U000E0041there\n")
	findings, err := plainify.ScanFile(path, "file.txt", plainify.Config{Fix: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d: %v", len(findings), findings)
	}
	if findings[0].Message != "zero-width character U+E0041 (Unicode tag character) - remove" {
		t.Errorf("unexpected message: %q", findings[0].Message)
	}

	if _, err := plainify.ScanFile(path, "file.txt", plainify.Config{Fix: true}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "hithere\n" {
		t.Errorf("tag character not removed: %q", got)
	}
}

func TestScanFile_VariationSelectorRemoved(t *testing.T) {
	t.Parallel()
	// VS1-VS14 outside emoji context can hide data in plain-looking text.
	path := writeFile(t, "file.txt", "a\uFE01b\n")
	findings, err := plainify.ScanFile(path, "file.txt", plainify.Config{Fix: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d: %v", len(findings), findings)
	}
	if findings[0].Message != "zero-width character U+FE01 (variation selector) - remove" {
		t.Errorf("unexpected message: %q", findings[0].Message)
	}

	if _, err := plainify.ScanFile(path, "file.txt", plainify.Config{Fix: true}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "ab\n" {
		t.Errorf("variation selector not removed: %q", got)
	}
}

func TestScanFile_TextPresentationSelectorAllowedInMarkdown(t *testing.T) {
	t.Parallel()
	// VS15 (text presentation) after an emoji base is legitimate in Markdown.
	path := writeFile(t, "doc.md", "skull \u2620\uFE0E here\n")
	findings, err := plainify.ScanFile(path, "doc.md", plainify.Config{Fix: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected text presentation sequence to be allowed, got: %v", findings)
	}
}

func TestScanFile_QuotesAndDashesFixed(t *testing.T) {
	t.Parallel()
	// Guillemets, German low quotes, prime, minus sign, non-breaking hyphen.
	path := writeFile(t, "file.txt", "\u00ABa\u00BB \u201Eb\u201C 5\u2032 3\u22122 x\u2011y\n")
	findings, err := plainify.ScanFile(path, "file.txt", plainify.Config{Fix: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings after fix, got: %v", findings)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "\"a\" \"b\" 5' 3-2 x-y\n" {
		t.Errorf("typographic characters not fixed: %q", got)
	}
}

func TestScanFile_UnicodeSpacesFixed(t *testing.T) {
	t.Parallel()
	// Narrow no-break space, em space, ideographic space.
	path := writeFile(t, "file.txt", "a\u202Fb\u2003c\u3000d\n")
	findings, err := plainify.ScanFile(path, "file.txt", plainify.Config{Fix: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings after fix, got: %v", findings)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "a b c d\n" {
		t.Errorf("unicode spaces not fixed: %q", got)
	}
}

func TestScanFile_FullwidthASCIIFixed(t *testing.T) {
	t.Parallel()
	path := writeFile(t, "file.txt", "\uFF28\uFF49\uFF01\n")
	findings, err := plainify.ScanFile(path, "file.txt", plainify.Config{Fix: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings after fix, got: %v", findings)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "Hi!\n" {
		t.Errorf("fullwidth ASCII not fixed: %q", got)
	}
}

func TestScanFile_LineSeparatorFixed(t *testing.T) {
	t.Parallel()
	// U+2028 breaks JavaScript string literals and is invisible in editors.
	path := writeFile(t, "file.txt", "a\u2028b\n")
	findings, err := plainify.ScanFile(path, "file.txt", plainify.Config{Fix: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings after fix, got: %v", findings)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "a\nb\n" {
		t.Errorf("line separator not converted: %q", got)
	}
}

func TestScanFile_MojibakeDetected(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, content, wantSeq string
	}{
		{"cp1252-apostrophe", "don\u00E2\u20AC\u2122t stop\n", "\u00E2\u20AC"},
		{"latin1-umlaut", "M\u00C3\u00BCller\n", "\u00C3\u00BC"},
		{"latin1-nbsp", "price\u00C2\u00A0100\n", "\u00C2\\u00a0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := writeFile(t, "file.txt", tc.content)
			findings, err := plainify.ScanFile(path, "file.txt", plainify.Config{Fix: false})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(findings) != 1 {
				t.Fatalf("expected one mojibake finding, got %d: %v", len(findings), findings)
			}
			want := "possible mojibake \"" + tc.wantSeq + "\" (UTF-8 read as Latin-1/CP1252) - re-encode the file"
			if findings[0].Message != want {
				t.Errorf("message = %q, want %q", findings[0].Message, want)
			}

			// Fix mode must not rewrite the file: character-level fixes would
			// destroy the ability to repair it by re-encoding.
			if _, err := plainify.ScanFile(path, "file.txt", plainify.Config{Fix: true}); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			got, _ := os.ReadFile(path)
			if string(got) != tc.content {
				t.Errorf("mojibake file must not be rewritten: %q", got)
			}
		})
	}
}

func TestScanFile_MojibakeNoFalsePositive(t *testing.T) {
	t.Parallel()
	// Legitimate accented words: the lead characters are followed by ASCII.
	path := writeFile(t, "file.txt", "S\u00C3O PAULO bl\u00E2me\n")
	findings, err := plainify.ScanFile(path, "file.txt", plainify.Config{Fix: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if strings.HasPrefix(f.Message, "possible mojibake") {
			t.Errorf("false positive mojibake finding: %q", f.Message)
		}
	}
}

func TestScanFile_CombiningMarkNFDHint(t *testing.T) {
	t.Parallel()
	// Decomposed u-umlaut (u + combining diaeresis), e.g. from macOS file APIs.
	path := writeFile(t, "file.txt", "u\u0308ber\n")
	findings, err := plainify.ScanFile(path, "file.txt", plainify.Config{Fix: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d: %v", len(findings), findings)
	}
	want := "combining mark U+0308 (decomposed character) - normalize to NFC"
	if findings[0].Message != want {
		t.Errorf("message = %q, want %q", findings[0].Message, want)
	}
}

func TestScanFile_BrokenSymlink(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	link := filepath.Join(dir, "link")
	if err := os.Symlink(filepath.Join(dir, "nonexistent-target"), link); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	findings, err := plainify.ScanFile(link, "link", plainify.Config{Fix: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one broken-symlink finding, got %d: %v", len(findings), findings)
	}
	if !strings.HasPrefix(findings[0].Message, "broken symlink -> ") {
		t.Errorf("unexpected message: %q", findings[0].Message)
	}
}

func TestScanFile_ValidSymlinkNotFollowed(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Target contains issues (CRLF); the symlink must not surface them and
	// must not be rewritten in fix mode.
	target := filepath.Join(dir, "target.txt")
	if err := os.WriteFile(target, []byte("line1\r\nline2\r\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	findings, err := plainify.ScanFile(link, "link.txt", plainify.Config{Fix: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected valid symlink to be skipped, got: %v", findings)
	}
	// The target must be untouched (fix must not follow the link).
	got, _ := os.ReadFile(target)
	if string(got) != "line1\r\nline2\r\n" {
		t.Errorf("symlink target must not be rewritten: %q", got)
	}
}

func TestScanFile_DirectorySkipped(t *testing.T) {
	t.Parallel()
	// A submodule gitlink is listed by git ls-files as a directory path.
	dir := t.TempDir()
	findings, err := plainify.ScanFile(dir, "mysub", plainify.Config{Fix: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected directory to be skipped, got: %v", findings)
	}
}

func TestScanFile_LFSPointerDetected(t *testing.T) {
	t.Parallel()
	// LFS pointer with a binary extension: detection must precede skipExts.
	pointer := "version https://git-lfs.github.com/spec/v1\n" +
		"oid sha256:4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d17e2393\n" +
		"size 12345\n"
	path := writeFile(t, "asset.png", pointer)
	findings, err := plainify.ScanFile(path, "asset.png", plainify.Config{Fix: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one LFS finding, got %d: %v", len(findings), findings)
	}
	if findings[0].Message != "Git LFS pointer (object not checked out) - run git lfs pull" {
		t.Errorf("unexpected message: %q", findings[0].Message)
	}
	// Must not be rewritten.
	got, _ := os.ReadFile(path)
	if string(got) != pointer {
		t.Errorf("LFS pointer must not be rewritten: %q", got)
	}
}

func TestScanFile_ConflictMarkersDetected(t *testing.T) {
	t.Parallel()
	content := "line\n<<<<<<< HEAD\nours\n=======\ntheirs\n>>>>>>> feature\ntail\n"
	path := writeFile(t, "file.txt", content)
	findings, err := plainify.ScanFile(path, "file.txt", plainify.Config{Fix: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("expected three conflict-marker findings, got %d: %v", len(findings), findings)
	}
	for _, f := range findings {
		if f.Message != "merge conflict marker - resolve the conflict" {
			t.Errorf("unexpected message: %q", f.Message)
		}
	}
	if findings[0].Line != 2 || findings[1].Line != 4 || findings[2].Line != 6 {
		t.Errorf("unexpected lines: %v", findings)
	}
}

func TestScanFile_SetextHeadingNotConflict(t *testing.T) {
	t.Parallel()
	// A setext H1 underline (=======) with no angle markers is not a conflict.
	path := writeFile(t, "doc.md", "Title\n=======\n\nbody\n")
	findings, err := plainify.ScanFile(path, "doc.md", plainify.Config{Fix: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if strings.HasPrefix(f.Message, "merge conflict marker") {
			t.Errorf("false positive conflict marker on setext heading: %v", f)
		}
	}
}

func TestScanFile_DecorativeSeparatorNotConflict(t *testing.T) {
	t.Parallel()
	// Longer runs than 7 chars must never be treated as conflict markers,
	// even alongside real angle markers elsewhere.
	content := "<<<<<<< HEAD\nx\n========\ny\n>>>>>>> branch\n"
	path := writeFile(t, "file.txt", content)
	findings, err := plainify.ScanFile(path, "file.txt", plainify.Config{Fix: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Only the two angle markers count; the 8-char "========" does not.
	count := 0
	for _, f := range findings {
		if strings.HasPrefix(f.Message, "merge conflict marker") {
			count++
		}
	}
	if count != 2 {
		t.Errorf("expected 2 conflict markers (8-char separator excluded), got %d: %v", count, findings)
	}
}
