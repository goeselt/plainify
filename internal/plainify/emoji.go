package plainify

// Emoji policy: emoji are legitimate content in Markdown-like files
// (documentation and agent instruction files) and are tolerated there.
// In every other file they surface as non-ASCII findings. Emoji are never
// rewritten.

// emojiAllowedExts lists extensions of Markdown-like files in which emoji are
// allowed, including agent instruction formats such as Cursor rules (.mdc).
var emojiAllowedExts = map[string]bool{
	".md":       true,
	".markdown": true,
	".mdx":      true,
	".mdc":      true,
	".adoc":     true,
	".asciidoc": true,
	".rst":      true,
}

// isEmojiBase reports whether r is an emoji base character. The ranges follow
// the Unicode emoji blocks (UTS #51, https://unicode.org/reports/tr51/) at
// block granularity: slight over-matching only widens what Markdown-like
// files tolerate; detection in all other files is unaffected.
func isEmojiBase(r rune) bool {
	switch {
	case r >= 0x1F000 && r <= 0x1FAFF:
		// SMP emoji blocks: pictographs, emoticons, transport, regional
		// indicators (flags), skin tone modifiers, supplemental symbols,
		// symbols extended-A.
		return true
	case r >= 0x2600 && r <= 0x27BF:
		// Miscellaneous Symbols and Dingbats.
		return true
	case r >= 0x2194 && r <= 0x2199, r == 0x21A9, r == 0x21AA:
		// Emoji arrows.
		return true
	case r >= 0x23E9 && r <= 0x23F3, r >= 0x23F8 && r <= 0x23FA:
		// Media controls and clocks.
		return true
	case r == 0x25AA, r == 0x25AB, r == 0x25B6, r == 0x25C0,
		r >= 0x25FB && r <= 0x25FE:
		// Geometric shapes used as emoji.
		return true
	case r >= 0x2B05 && r <= 0x2B07, r == 0x2B1B, r == 0x2B1C,
		r == 0x2B50, r == 0x2B55:
		// Arrows, large squares, star, circle.
		return true
	case r == 0x00A9, r == 0x00AE, r == 0x203C, r == 0x2049,
		r == 0x2122, r == 0x2139:
		// Copyright, registered, double exclamation, interrobang,
		// trade mark, information source.
		return true
	case r == 0x231A, r == 0x231B, r == 0x2328, r == 0x23CF, r == 0x24C2:
		// Watch, hourglass, keyboard, eject, circled M.
		return true
	case r == 0x2934, r == 0x2935, r == 0x3030, r == 0x303D,
		r == 0x3297, r == 0x3299:
		// Arrow heading up/down, wavy dash, part alternation mark,
		// circled congratulation/secret ideographs.
		return true
	}
	return false
}

// isKeycapBase reports whether r can start a keycap sequence
// (digit, '#', or '*' followed by U+FE0F U+20E3).
func isKeycapBase(r rune) bool {
	return (r >= '0' && r <= '9') || r == '#' || r == '*'
}

// isEmojiSequenceRune reports whether runes[i] is part of a well-formed emoji
// sequence: an emoji base, or a variation selector, combining keycap, or
// zero-width joiner in emoji context. The same combining characters outside
// emoji context are not covered and remain findings.
func isEmojiSequenceRune(runes []rune, i int) bool {
	switch r := runes[i]; r {
	case 0xFE0E, 0xFE0F: // variation selector-15/16: text/emoji presentation
		return i > 0 && (isEmojiBase(runes[i-1]) || isKeycapBase(runes[i-1]))
	case 0x20E3: // combining enclosing keycap
		if i > 0 && isKeycapBase(runes[i-1]) {
			return true
		}
		return i > 1 && runes[i-1] == 0xFE0F && isKeycapBase(runes[i-2])
	case 0x200D: // zero-width joiner between emoji (e.g. family sequences)
		if i == 0 || i+1 >= len(runes) {
			return false
		}
		prev := runes[i-1]
		return (isEmojiBase(prev) || prev == 0xFE0F) && isEmojiBase(runes[i+1])
	default:
		return isEmojiBase(r)
	}
}
