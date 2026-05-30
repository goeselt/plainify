// Package plainify detects and fixes encoding issues, CRLF line endings,
// non-ASCII typographic characters, invisible characters, bidirectional
// control characters, stray control characters, and emoji in text files.
package plainify

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// skipExts lists file extensions that are always treated as binary and skipped.
var skipExts = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
	".bmp": true, ".ico": true, ".webp": true,
	".woff": true, ".woff2": true, ".ttf": true, ".otf": true, ".eot": true,
	".zip": true, ".tar": true, ".gz": true, ".bz2": true, ".xz": true, ".7z": true,
	".pdf": true,
	".exe": true, ".dll": true, ".so": true, ".dylib": true,
	".o": true, ".a": true, ".pyc": true, ".pyo": true,
	".class": true, ".jar": true, ".war": true,
	".lock": true,
}

// replacements maps common non-ASCII typographic characters to ASCII equivalents.
// These frequently appear in AI-generated text or content pasted from word processors.
var replacements = map[rune]string{
	'\u2014': "--",  // em-dash
	'\u2013': "--",  // en-dash
	'\u2192': "-->", // rightwards arrow
	'\u2190': "<--", // leftwards arrow
	'\u21D2': "=>",  // rightwards double arrow
	'\u2018': "'",   // left single quotation mark
	'\u2019': "'",   // right single quotation mark
	'\u201C': `"`,   // left double quotation mark
	'\u201D': `"`,   // right double quotation mark
	'\u00A0': " ",   // non-breaking space
	'\u2026': "...", // horizontal ellipsis
	'\u2022': "-",   // bullet
	'\u2514': "+",   // box drawings light up and right
	'\u251C': "+",   // box drawings light vertical and right
	'\u2500': "-",   // box drawings light horizontal
	'\u2502': "|",   // box drawings light vertical
}

// invisibles maps zero-width and bidirectional control characters to a short name.
// These are deleted (replaced with empty string) in fix mode.
//
// Zero-width characters are invisible in editors and silently break string
// comparisons and regex matches. Bidirectional control characters are the basis
// of the Trojan Source attack (CVE-2021-42574), where code appears different
// in an editor than what the compiler sees.
var invisibles = map[rune]string{
	// Zero-width characters
	'\u00AD': "soft hyphen",
	'\u200B': "zero-width space",
	'\u200C': "zero-width non-joiner",
	'\u200D': "zero-width joiner",
	// Bidirectional control characters (Trojan Source / CVE-2021-42574)
	'\u200E': "left-to-right mark",
	'\u200F': "right-to-left mark",
	'\u202A': "left-to-right embedding",
	'\u202B': "right-to-left embedding",
	'\u202C': "pop directional formatting",
	'\u202D': "left-to-right override",
	'\u202E': "right-to-left override",
	'\u2066': "left-to-right isolate",
	'\u2067': "right-to-left isolate",
	'\u2068': "first strong isolate",
	'\u2069': "pop directional isolate",
	'\u061C': "arabic letter mark",
}

// isBidiControl returns true if r is a Unicode bidirectional control character.
func isBidiControl(r rune) bool {
	return r == '\u200E' || r == '\u200F' || r == '\u061C' ||
		(r >= '\u202A' && r <= '\u202E') ||
		(r >= '\u2066' && r <= '\u2069')
}

// isStrayControl returns true if r is a C0 control character that should not
// appear in text files. Excludes tab (\t), newline (\n), and carriage return (\r)
// which are handled separately.
func isStrayControl(r rune) bool {
	if r == '\t' || r == '\n' || r == '\r' {
		return false
	}
	return r >= 0x00 && r <= 0x1F
}

// Config controls how ScanFile behaves.
type Config struct {
	Fix          bool // Rewrite fixable issues in place.
	AllowUtf8Bom bool // Do not flag UTF-8 BOM.
}

// Finding represents a single normalization issue.
type Finding struct {
	File    string `json:"file"`
	Line    int    `json:"line,omitempty"`
	Col     int    `json:"col,omitempty"`
	Message string `json:"message"`
}

// ScanFile scans a single file for normalization issues.
// Binary files and files with known binary extensions are silently skipped.
// In fix mode, fixable issues are rewritten in place; any remaining unfixable
// issues (e.g., arbitrary non-ASCII bytes) are returned as findings.
func ScanFile(absPath, relPath string, cfg Config) ([]Finding, error) {
	ext := strings.ToLower(filepath.Ext(absPath))
	if skipExts[ext] {
		return nil, nil
	}

	f, err := os.Open(absPath)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", relPath, err)
	}
	defer func() { _ = f.Close() }()

	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", relPath, err)
	}

	// Read only the first 8 KB to decide encoding and binary status before
	// committing to loading the entire file into memory.
	header := make([]byte, 8192)
	n, err := f.Read(header)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("read %s: %w", relPath, err)
	}
	header = header[:n]

	// Encoding detection must precede binary check: UTF-16 files contain null bytes.
	// UTF-16 is unfixable -- always short-circuit. UTF-8 BOM is fixable in fix mode.
	if finding := detectUTF16(header, relPath); finding != nil {
		return []Finding{*finding}, nil
	}
	if isBinary(header) {
		return nil, nil
	}

	// File is text: read the remainder and concatenate with the already-read header.
	rest, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", relPath, err)
	}
	buf := append(header, rest...)

	// Strip or fix UTF-8 BOM.
	hasBOM := len(buf) >= 3 && buf[0] == 0xEF && buf[1] == 0xBB && buf[2] == 0xBF
	if hasBOM && cfg.AllowUtf8Bom {
		buf = buf[3:]
	}
	return scanText(absPath, relPath, ext, string(buf), hasBOM, fi.Mode(), cfg)
}

// detectUTF16 identifies UTF-16 encoded files (BOM or heuristic).
// UTF-16 is not auto-fixable and always produces a finding.
func detectUTF16(buf []byte, relPath string) *Finding {
	if len(buf) < 2 {
		return nil
	}
	switch {
	case buf[0] == 0xFF && buf[1] == 0xFE:
		return &Finding{File: relPath, Line: 1, Col: 1, Message: "UTF-16 LE (BOM FF FE) - convert to UTF-8"}
	case buf[0] == 0xFE && buf[1] == 0xFF:
		return &Finding{File: relPath, Line: 1, Col: 1, Message: "UTF-16 BE (BOM FE FF) - convert to UTF-8"}
	}
	// Heuristic: high ratio of null bytes at alternating positions indicates UTF-16 without BOM.
	if len(buf) >= 4 {
		sample := min(len(buf), 64)
		nullOdd, nullEven := 0, 0
		for i := range sample {
			if buf[i] == 0 {
				if i%2 == 0 {
					nullEven++
				} else {
					nullOdd++
				}
			}
		}
		threshold := sample / 4
		if nullOdd >= threshold && nullEven == 0 {
			return &Finding{File: relPath, Line: 1, Col: 1, Message: "UTF-16 LE (no BOM, null-byte heuristic) - convert to UTF-8"}
		}
		if nullEven >= threshold && nullOdd == 0 {
			return &Finding{File: relPath, Line: 1, Col: 1, Message: "UTF-16 BE (no BOM, null-byte heuristic) - convert to UTF-8"}
		}
	}
	return nil
}

// isBinary returns true if buf appears to be a binary (non-text) file.
func isBinary(buf []byte) bool {
	limit := min(len(buf), 8192)
	for i := range limit {
		if buf[i] == 0 {
			return true
		}
	}
	return false
}

// scanText makes plain a decoded text file.
// In fix mode: applies all fixes, writes if changed, returns any remaining non-ASCII.
// In check mode: returns all issues found without modifying the file.
func scanText(absPath, relPath, ext, content string, hasBOM bool, perm os.FileMode, cfg Config) ([]Finding, error) {
	if cfg.Fix {
		fixed := content
		// Remove UTF-8 BOM (unless allowed).
		if hasBOM && !cfg.AllowUtf8Bom {
			fixed = strings.TrimPrefix(fixed, "\xEF\xBB\xBF")
		}
		fixed = strings.ReplaceAll(fixed, "\r\n", "\n")
		fixed = applyCharFixes(fixed)
		fixed = removeStrayControls(fixed)
		if ext == ".md" {
			fixed = ReplaceEmoji(fixed)
		}
		if fixed != content {
			if err := os.WriteFile(absPath, []byte(fixed), perm); err != nil {
				return nil, fmt.Errorf("write %s: %w", relPath, err)
			}
			content = fixed
		}
		return findNonASCII(relPath, content), nil
	}

	var findings []Finding
	if hasBOM && !cfg.AllowUtf8Bom {
		findings = append(findings, Finding{File: relPath, Line: 1, Col: 1, Message: "UTF-8 BOM (EF BB BF) - remove for portability"})
	}
	findings = append(findings, findCRLF(relPath, content)...)
	findings = append(findings, findReplacements(relPath, content)...)
	findings = append(findings, findInvisibles(relPath, content)...)
	findings = append(findings, findStrayControls(relPath, content)...)
	if ext == ".md" {
		findings = append(findings, FindEmojiFindings(relPath, content)...)
	}
	findings = append(findings, findNonASCII(relPath, content)...)
	return findings, nil
}

func findCRLF(relPath, content string) []Finding {
	hasCRLF := strings.Contains(content, "\r\n")
	if !hasCRLF {
		return nil
	}
	// Detect mixed line endings: file has both CRLF and bare LF.
	stripped := strings.ReplaceAll(content, "\r\n", "")
	if strings.Contains(stripped, "\n") {
		return []Finding{{File: relPath, Line: 1, Message: "mixed line endings (CRLF and LF) - convert to LF"}}
	}
	return []Finding{{File: relPath, Line: 1, Message: "CRLF line endings - convert to LF"}}
}

// applyCharFixes replaces all typographic characters with ASCII equivalents
// and deletes all invisible/bidirectional control characters.
func applyCharFixes(content string) string {
	var sb strings.Builder
	sb.Grow(len(content))
	for _, r := range content {
		if repl, ok := replacements[r]; ok {
			sb.WriteString(repl)
		} else if _, ok := invisibles[r]; ok {
			// delete -- write nothing
		} else {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// removeStrayControls deletes C0 control characters (except \t, \n, \r)
// including form feed (\f) and vertical tab (\v).
func removeStrayControls(content string) string {
	var sb strings.Builder
	sb.Grow(len(content))
	for _, r := range content {
		if !isStrayControl(r) {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

func findReplacements(relPath, content string) []Finding {
	var findings []Finding
	for i, line := range strings.Split(content, "\n") {
		for col, r := range line {
			if _, ok := replacements[r]; ok {
				findings = append(findings, Finding{
					File:    relPath,
					Line:    i + 1,
					Col:     col + 1,
					Message: fmt.Sprintf("non-ASCII typographic character U+%04X - use ASCII equivalent", r),
				})
				break // one per line
			}
		}
	}
	return findings
}

func findInvisibles(relPath, content string) []Finding {
	var findings []Finding
	for i, line := range strings.Split(content, "\n") {
		for col, r := range line {
			if name, ok := invisibles[r]; ok {
				msg := fmt.Sprintf("zero-width character U+%04X (%s) - remove", r, name)
				if isBidiControl(r) {
					msg = fmt.Sprintf("bidirectional control character U+%04X (%s) - remove (Trojan Source risk)", r, name)
				}
				findings = append(findings, Finding{
					File:    relPath,
					Line:    i + 1,
					Col:     col + 1,
					Message: msg,
				})
				break // one per line
			}
		}
	}
	return findings
}

// strayControlNames maps stray C0 control characters to human-readable names.
var strayControlNames = map[rune]string{
	'\x01': "SOH", '\x02': "STX", '\x03': "ETX", '\x04': "EOT",
	'\x05': "ENQ", '\x06': "ACK", '\x07': "BEL", '\x08': "BS",
	'\x0B': "VT", '\x0C': "FF", '\x0E': "SO", '\x0F': "SI",
	'\x10': "DLE", '\x11': "DC1", '\x12': "DC2", '\x13': "DC3",
	'\x14': "DC4", '\x15': "NAK", '\x16': "SYN", '\x17': "ETB",
	'\x18': "CAN", '\x19': "EM", '\x1A': "SUB", '\x1B': "ESC",
	'\x1C': "FS", '\x1D': "GS", '\x1E': "RS", '\x1F': "US",
}

func findStrayControls(relPath, content string) []Finding {
	var findings []Finding
	for i, line := range strings.Split(content, "\n") {
		for col, r := range line {
			if isStrayControl(r) {
				name := strayControlNames[r]
				findings = append(findings, Finding{
					File:    relPath,
					Line:    i + 1,
					Col:     col + 1,
					Message: fmt.Sprintf("stray control character 0x%02X (%s) - remove", r, name),
				})
				break // one per line
			}
		}
	}
	return findings
}

// findNonASCII reports non-ASCII bytes that are not already handled by
// findReplacements or findInvisibles (which have more specific messages).
func findNonASCII(relPath, content string) []Finding {
	var findings []Finding
	for i, line := range strings.Split(content, "\n") {
		for col, r := range line {
			if r <= 0x7F {
				continue
			}
			if _, ok := replacements[r]; ok {
				continue
			}
			if _, ok := invisibles[r]; ok {
				continue
			}
			findings = append(findings, Finding{
				File:    relPath,
				Line:    i + 1,
				Col:     col + 1,
				Message: fmt.Sprintf("non-ASCII character U+%04X", r),
			})
			break // one per line
		}
	}
	return findings
}
