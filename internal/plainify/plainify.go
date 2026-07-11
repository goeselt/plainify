// Package plainify detects and fixes encoding issues, CRLF line endings,
// non-ASCII typographic characters, invisible characters, bidirectional
// control characters, and stray control characters in text files. Emoji are
// tolerated in Markdown-like files and reported as non-ASCII findings
// everywhere else; they are never rewritten.
package plainify

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
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
// Fullwidth ASCII variants (U+FF01-U+FF5E) are handled by asciiReplacement.
var replacements = map[rune]string{
	'\u2014': "--",  // em-dash
	'\u2013': "--",  // en-dash
	'\u2010': "-",   // hyphen
	'\u2011': "-",   // non-breaking hyphen
	'\u2012': "--",  // figure dash
	'\u2015': "--",  // horizontal bar
	'\u2212': "-",   // minus sign
	'\u2192': "-->", // rightwards arrow
	'\u2190': "<--", // leftwards arrow
	'\u21D2': "=>",  // rightwards double arrow
	'\u2018': "'",   // left single quotation mark
	'\u2019': "'",   // right single quotation mark
	'\u201A': "'",   // single low-9 quotation mark
	'\u201B': "'",   // single high-reversed-9 quotation mark
	'\u201C': `"`,   // left double quotation mark
	'\u201D': `"`,   // right double quotation mark
	'\u201E': `"`,   // double low-9 quotation mark
	'\u201F': `"`,   // double high-reversed-9 quotation mark
	'\u00AB': `"`,   // left guillemet
	'\u00BB': `"`,   // right guillemet
	'\u2039': "'",   // single left guillemet
	'\u203A': "'",   // single right guillemet
	'\u2032': "'",   // prime
	'\u2033': `"`,   // double prime
	'\u2026': "...", // horizontal ellipsis
	'\u2022': "-",   // bullet
	'\u2028': "\n",  // line separator (breaks JavaScript strings)
	'\u2029': "\n",  // paragraph separator (breaks JavaScript strings)
	'\u2514': "+",   // box drawings light up and right
	'\u251C': "+",   // box drawings light vertical and right
	'\u2500': "-",   // box drawings light horizontal
	'\u2502': "|",   // box drawings light vertical
	// Unicode space characters
	'\u00A0': " ", // non-breaking space
	'\u2000': " ", '\u2001': " ", '\u2002': " ", '\u2003': " ",
	'\u2004': " ", '\u2005': " ", '\u2006': " ", '\u2007': " ",
	'\u2008': " ", '\u2009': " ", '\u200A': " ", // en quad .. hair space
	'\u202F': " ", // narrow no-break space
	'\u205F': " ", // medium mathematical space
	'\u3000': " ", // ideographic space
}

// asciiReplacement returns the ASCII equivalent for typographic characters,
// covering the replacements table and fullwidth ASCII variants.
func asciiReplacement(r rune) (string, bool) {
	if repl, ok := replacements[r]; ok {
		return repl, true
	}
	// Fullwidth ASCII variants map 1:1 onto ASCII 0x21-0x7E.
	if r >= 0xFF01 && r <= 0xFF5E {
		return string(r - 0xFEE0), true
	}
	return "", false
}

// invisibles maps zero-width and bidirectional control characters to a short name.
// These are deleted (replaced with empty string) in fix mode; range-based cases
// (variation selectors, Unicode tag characters) are handled by invisibleName.
//
// Zero-width characters are invisible in editors and silently break string
// comparisons and regex matches. Bidirectional control characters are the basis
// of the Trojan Source attack (CVE-2021-42574), where code appears different
// in an editor than what the compiler sees. Variation selectors and Unicode tag
// characters are known channels for hiding data in plain-looking text.
var invisibles = map[rune]string{
	// Zero-width characters
	'\u00AD': "soft hyphen",
	'\u180E': "mongolian vowel separator",
	'\u200B': "zero-width space",
	'\u200C': "zero-width non-joiner",
	'\u200D': "zero-width joiner",
	'\u2060': "word joiner",
	'\uFEFF': "zero-width no-break space",
	// Invisible mathematical operators
	'\u2061': "invisible function application",
	'\u2062': "invisible times",
	'\u2063': "invisible separator",
	'\u2064': "invisible plus",
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

// invisibleName returns the descriptive name for invisible characters,
// covering the invisibles table plus range-based cases. U+FE0E/U+FE0F are
// excluded: as text/emoji presentation selectors they are handled by the
// emoji sequence logic.
func invisibleName(r rune) (string, bool) {
	if name, ok := invisibles[r]; ok {
		return name, true
	}
	switch {
	case r >= 0xFE00 && r <= 0xFE0D:
		return "variation selector", true
	case r >= 0xE0000 && r <= 0xE007F:
		return "Unicode tag character", true
	}
	return "", false
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

// utf8BOM is the UTF-8 byte order mark (U+FEFF encoded as UTF-8).
const utf8BOM = "\xEF\xBB\xBF"

// Config controls how ScanFile behaves.
type Config struct {
	Fix          bool // Rewrite fixable issues in place.
	AllowUtf8Bom bool // Do not flag UTF-8 BOM.
}

// Finding represents a single normalization issue.
// Line and Col are 1-based; Col counts runes, not bytes.
type Finding struct {
	File    string `json:"file"`
	Line    int    `json:"line,omitempty"`
	Col     int    `json:"col,omitempty"`
	Message string `json:"message"`
}

// ScanFile scans a single file for normalization issues.
// Symlinks are checked for a valid target but never followed; directories
// (e.g. submodule gitlinks), binary files, and known binary extensions are
// silently skipped. In fix mode, fixable issues are rewritten in place; any
// remaining unfixable issues (e.g., arbitrary non-ASCII bytes) are returned
// as findings.
func ScanFile(absPath, relPath string, cfg Config) ([]Finding, error) {
	// Lstat, not Stat: a symlink must be inspected as the link itself, never
	// followed. Following would let fix mode rewrite a file outside the
	// workspace and would rescan targets that git lists in their own right.
	info, err := os.Lstat(absPath)
	if err != nil {
		return nil, fmt.Errorf("lstat %s: %w", relPath, err)
	}
	switch {
	case info.Mode()&os.ModeSymlink != 0:
		return scanSymlink(absPath, relPath)
	case info.IsDir():
		// Submodule gitlink or plain directory entry: nothing to scan.
		return nil, nil
	case !info.Mode().IsRegular():
		// Device, socket, FIFO, etc.
		return nil, nil
	}

	ext := strings.ToLower(filepath.Ext(absPath))

	f, err := os.Open(absPath)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", relPath, err)
	}
	defer func() { _ = f.Close() }()

	// Read only the first 8 KB to decide encoding and binary status before
	// committing to loading the entire file into memory.
	header := make([]byte, 8192)
	n, err := f.Read(header)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("read %s: %w", relPath, err)
	}
	header = header[:n]

	// LFS pointer detection precedes the binary-extension skip: pointer files
	// stand in for binary assets and therefore usually carry binary extensions.
	if finding := detectLFSPointer(header, relPath); finding != nil {
		return []Finding{*finding}, nil
	}
	if skipExts[ext] {
		return nil, nil
	}

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
	// Re-check the remainder: a null byte after the header still marks the
	// file as binary and must not be "fixed" as a stray control character.
	if isBinary(rest) {
		return nil, nil
	}
	header = append(header, rest...)

	hasBOM := len(header) >= 3 && header[0] == 0xEF && header[1] == 0xBB && header[2] == 0xBF
	if finding := findInvalidUTF8(relPath, header); finding != nil {
		return []Finding{*finding}, nil
	}
	// Mojibake needs re-encoding of the whole file; like the encoding checks
	// above it short-circuits so that character-level fixes cannot corrupt
	// the file further.
	if findings := findMojibake(relPath, string(header)); len(findings) > 0 {
		return findings, nil
	}
	return scanText(absPath, relPath, ext, string(header), hasBOM, info.Mode(), cfg)
}

// lfsPointerPrefix is the fixed opening line of a Git LFS pointer file
// (https://github.com/git-lfs/git-lfs/blob/main/docs/spec.md). Its presence in
// the working tree means the real object was never checked out.
const lfsPointerPrefix = "version https://git-lfs.github.com/spec/"

// detectLFSPointer reports a file whose content is a Git LFS pointer rather
// than the object it stands for. Not auto-fixable: the object must be fetched.
func detectLFSPointer(header []byte, relPath string) *Finding {
	if !bytes.HasPrefix(header, []byte(lfsPointerPrefix)) {
		return nil
	}
	return &Finding{
		File:    relPath,
		Line:    1,
		Col:     1,
		Message: "Git LFS pointer (object not checked out) - run git lfs pull",
	}
}

// scanSymlink reports broken symlinks and skips valid ones. A symlink is never
// followed: git tracks only the link path, and a valid target that lives in
// the repository is scanned in its own right.
func scanSymlink(absPath, relPath string) ([]Finding, error) {
	target, err := os.Readlink(absPath)
	if err != nil {
		return nil, fmt.Errorf("readlink %s: %w", relPath, err)
	}
	resolved := target
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(filepath.Dir(absPath), target)
	}
	if _, err := os.Stat(resolved); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []Finding{{
				File:    relPath,
				Message: fmt.Sprintf("broken symlink -> %s", target),
			}}, nil
		}
		return nil, fmt.Errorf("stat symlink target %s: %w", relPath, err)
	}
	return nil, nil
}

func findInvalidUTF8(relPath string, buf []byte) *Finding {
	line, col := 1, 1
	for len(buf) > 0 {
		r, size := utf8.DecodeRune(buf)
		if r == utf8.RuneError && size == 1 {
			return &Finding{
				File:    relPath,
				Line:    line,
				Col:     col,
				Message: fmt.Sprintf("invalid UTF-8 byte 0x%02X - convert to UTF-8", buf[0]),
			}
		}
		if r == '\n' {
			line++
			col = 1
		} else {
			col++
		}
		buf = buf[size:]
	}
	return nil
}

// cp1252Followers lists characters that appear when a UTF-8 continuation byte
// (0x80-0xBF) is misread as Windows-1252 text: the printable CP1252 mappings
// of that byte range. Latin-1 misreads yield the raw code points U+0080-U+00BF
// instead, which isMojibakeFollower covers via a range check.
var cp1252Followers = map[rune]bool{
	'\u20AC': true, '\u201A': true, '\u0192': true, '\u201E': true,
	'\u2026': true, '\u2020': true, '\u2021': true, '\u02C6': true,
	'\u2030': true, '\u0160': true, '\u2039': true, '\u0152': true,
	'\u017D': true, '\u2018': true, '\u2019': true, '\u201C': true,
	'\u201D': true, '\u2022': true, '\u2013': true, '\u2014': true,
	'\u02DC': true, '\u2122': true, '\u0161': true, '\u203A': true,
	'\u0153': true, '\u017E': true, '\u0178': true,
}

func isMojibakeFollower(r rune) bool {
	return (r >= 0x80 && r <= 0xBF) || cp1252Followers[r]
}

// findMojibake detects double-encoded UTF-8: UTF-8 bytes that were read as
// Latin-1/CP1252 and re-encoded, e.g. U+00C3 U+00A9 where an e-acute was
// meant, or U+00E2 U+20AC U+2122 for a right single quotation mark. The
// signature is a re-encoded UTF-8 lead byte (U+00C2 A-circumflex, U+00C3
// A-tilde, U+00E2 a-circumflex) directly followed by a re-encoded
// continuation byte.
// Mojibake is reported one finding per line and never auto-fixed: the file
// must be repaired by re-encoding, and individual character fixes would
// destroy that possibility.
func findMojibake(relPath, content string) []Finding {
	var findings []Finding
	for i, line := range strings.Split(content, "\n") {
		runes := []rune(line)
		for col := 0; col+1 < len(runes); col++ {
			r := runes[col]
			if (r == 0x00C2 || r == 0x00C3 || r == 0x00E2) && isMojibakeFollower(runes[col+1]) {
				findings = append(findings, Finding{
					File:    relPath,
					Line:    i + 1,
					Col:     col + 1,
					Message: fmt.Sprintf("possible mojibake %q (UTF-8 read as Latin-1/CP1252) - re-encode the file", string(runes[col:col+2])),
				})
				break // one per line
			}
		}
	}
	return findings
}

// conflictMarkers are the line prefixes git writes for an unresolved merge.
var conflictMarkers = []string{"<<<<<<<", "|||||||", "=======", ">>>>>>>"}

// isConflictMarker reports whether line is exactly the 7-character marker,
// optionally followed by a space and a label. This rejects longer runs such as
// a decorative "========" or a Markdown setext underline "====".
func isConflictMarker(line, marker string) bool {
	if !strings.HasPrefix(line, marker) {
		return false
	}
	rest := strings.TrimSuffix(line[len(marker):], "\r")
	return rest == "" || strings.HasPrefix(rest, " ")
}

// findConflictMarkers reports unresolved merge conflict markers. To avoid
// flagging a lone "=======" setext heading, findings are emitted only when the
// content contains both an opening (<<<<<<<) and a closing (>>>>>>>) marker.
func findConflictMarkers(relPath, content string) []Finding {
	lines := strings.Split(content, "\n")
	hasStart, hasEnd := false, false
	for _, line := range lines {
		hasStart = hasStart || isConflictMarker(line, "<<<<<<<")
		hasEnd = hasEnd || isConflictMarker(line, ">>>>>>>")
	}
	if !hasStart || !hasEnd {
		return nil
	}
	var findings []Finding
	for i, line := range lines {
		for _, marker := range conflictMarkers {
			if isConflictMarker(line, marker) {
				findings = append(findings, Finding{
					File:    relPath,
					Line:    i + 1,
					Col:     1,
					Message: "merge conflict marker - resolve the conflict",
				})
				break
			}
		}
	}
	return findings
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

// isBinary returns true if buf contains a null byte, the marker for binary content.
func isBinary(buf []byte) bool {
	return bytes.IndexByte(buf, 0) >= 0
}

// scanText makes plain a decoded text file.
// In fix mode: applies all fixes, writes if changed, returns any remaining non-ASCII.
// In check mode: returns all issues found without modifying the file.
func scanText(absPath, relPath, ext, content string, hasBOM bool, perm os.FileMode, cfg Config) ([]Finding, error) {
	// Emoji are never rewritten: Markdown-like files keep them, all other
	// files report them via the non-ASCII check.
	allowEmoji := emojiAllowedExts[ext]

	if cfg.Fix {
		// Strip the BOM before the character fixes (U+FEFF is an invisible
		// character); re-prepend it when the BOM is allowed.
		fixed := strings.TrimPrefix(content, utf8BOM)
		fixed = strings.ReplaceAll(fixed, "\r\n", "\n")
		fixed = applyCharFixes(fixed, allowEmoji)
		fixed = removeStrayControls(fixed)
		if hasBOM && cfg.AllowUtf8Bom {
			fixed = utf8BOM + fixed
		}
		if fixed != content {
			if err := os.WriteFile(absPath, []byte(fixed), perm); err != nil {
				return nil, fmt.Errorf("write %s: %w", relPath, err)
			}
		}
		checkContent := strings.TrimPrefix(fixed, utf8BOM)
		var findings []Finding
		findings = append(findings, findConflictMarkers(relPath, checkContent)...)
		findings = append(findings, findNonASCII(relPath, checkContent, allowEmoji)...)
		return findings, nil
	}

	// The BOM is reported via its own finding below; scan the content
	// without it so U+FEFF is not reported a second time.
	checkContent := strings.TrimPrefix(content, utf8BOM)
	var findings []Finding
	if hasBOM && !cfg.AllowUtf8Bom {
		findings = append(findings, Finding{File: relPath, Line: 1, Col: 1, Message: "UTF-8 BOM (EF BB BF) - remove for portability"})
	}
	findings = append(findings, findCRLF(relPath, checkContent)...)
	findings = append(findings, findReplacements(relPath, checkContent)...)
	findings = append(findings, findInvisibles(relPath, checkContent, allowEmoji)...)
	findings = append(findings, findStrayControls(relPath, checkContent)...)
	findings = append(findings, findConflictMarkers(relPath, checkContent)...)
	findings = append(findings, findNonASCII(relPath, checkContent, allowEmoji)...)
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
// and deletes all invisible/bidirectional control characters. With allowEmoji,
// zero-width joiners inside emoji sequences are preserved so that multi-emoji
// sequences (e.g. family emoji) stay intact.
func applyCharFixes(content string, allowEmoji bool) string {
	runes := []rune(content)
	var sb strings.Builder
	sb.Grow(len(content))
	for i, r := range runes {
		if repl, ok := asciiReplacement(r); ok {
			sb.WriteString(repl)
		} else if _, ok := invisibleName(r); ok {
			if allowEmoji && isEmojiSequenceRune(runes, i) {
				sb.WriteRune(r)
			}
			// otherwise delete -- write nothing
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
		for col, r := range []rune(line) {
			if _, ok := asciiReplacement(r); ok {
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

func findInvisibles(relPath, content string, allowEmoji bool) []Finding {
	var findings []Finding
	for i, line := range strings.Split(content, "\n") {
		runes := []rune(line)
		for col, r := range runes {
			name, ok := invisibleName(r)
			if !ok {
				continue
			}
			if allowEmoji && isEmojiSequenceRune(runes, col) {
				continue // e.g. zero-width joiner inside an emoji sequence
			}
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
		for col, r := range []rune(line) {
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

// findNonASCII reports non-ASCII characters that are not already handled by
// findReplacements or findInvisibles (which have more specific messages).
// With allowEmoji, well-formed emoji sequences are tolerated; without it,
// emoji are reported with an "(emoji)" hint. Combining diacritical marks get
// a decomposed-character (NFD) hint.
func findNonASCII(relPath, content string, allowEmoji bool) []Finding {
	var findings []Finding
	for i, line := range strings.Split(content, "\n") {
		runes := []rune(line)
		for col, r := range runes {
			if r <= 0x7F {
				continue
			}
			if _, ok := asciiReplacement(r); ok {
				continue
			}
			if _, ok := invisibleName(r); ok {
				continue
			}
			partOfEmoji := isEmojiSequenceRune(runes, col)
			if allowEmoji && partOfEmoji {
				continue
			}
			msg := fmt.Sprintf("non-ASCII character U+%04X", r)
			switch {
			case partOfEmoji:
				msg += " (emoji)"
			case r >= 0x0300 && r <= 0x036F:
				msg = fmt.Sprintf("combining mark U+%04X (decomposed character) - normalize to NFC", r)
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
	return findings
}
