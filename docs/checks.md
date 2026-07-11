# Checks Reference

`plainify` makes one pass over each tracked file. Fixable issues are rewritten in place unless `--nofix` is set; the
rest are reported. Finding columns are 1-based and count runes, not bytes.

## Fixed In Place

### Line Endings

CRLF (`\r\n`) is converted to LF. A file mixing CRLF and bare LF is reported as `mixed line endings`.

### Typographic Characters

Replaced with their ASCII equivalents. These frequently arrive via AI-generated text or word-processor paste.

| Category                                      | Code points                                    | ASCII               |
| --------------------------------------------- | ---------------------------------------------- | ------------------- |
| Em / en dash, Unicode hyphens, horizontal bar | U+2014, U+2013, U+2010-U+2012, U+2015          | `--` / `-`          |
| Minus sign                                    | U+2212                                         | `-`                 |
| Single quotes, low quotes, single guillemets  | U+2018, U+2019, U+201A, U+201B, U+2039, U+203A | `'`                 |
| Double quotes, low quotes, guillemets         | U+201C-U+201F, U+00AB, U+00BB                  | `"`                 |
| Prime, double prime                           | U+2032, U+2033                                 | `'`, `"`            |
| Arrows                                        | U+2192, U+2190, U+21D2                         | `-->`, `<--`, `=>`  |
| Ellipsis                                      | U+2026                                         | `...`               |
| Bullet                                        | U+2022                                         | `-`                 |
| Box drawing                                   | U+2514, U+251C, U+2500, U+2502                 | `+`, `+`, `-`, `\|` |
| Unicode spaces                                | U+00A0, U+2000-U+200A, U+202F, U+205F, U+3000  | space               |
| Line / paragraph separators                   | U+2028, U+2029                                 | newline             |
| Fullwidth ASCII                               | U+FF01-U+FF5E                                  | ASCII 0x21-0x7E     |

### Invisible Characters

Deleted, because they are invisible in editors yet silently break string comparisons and regular expression matches:

- Zero-width space, non-joiner, joiner: U+200B, U+200C, U+200D
- Soft hyphen, Mongolian vowel separator: U+00AD, U+180E
- Word joiner, zero-width no-break space (mid-file): U+2060, U+FEFF
- Invisible mathematical operators: U+2061-U+2064
- Variation selectors: U+FE00-U+FE0D (U+FE0E and U+FE0F are kept inside valid emoji sequences)
- Unicode tag characters: U+E0000-U+E007F (a known data-smuggling channel)

A zero-width joiner is preserved when it sits inside a valid emoji sequence in a Markdown-like file.

### Bidirectional Control Characters

Deleted. These are the basis of the [Trojan Source](https://trojansource.codes) attack (CVE-2021-42574), where code
renders differently in an editor than what the compiler sees: U+200E, U+200F, U+202A-U+202E, U+2066-U+2069, U+061C.

### Stray Control Characters

C0 controls other than tab, newline, and carriage return are deleted, including form feed and vertical tab:
U+0001-U+0008, U+000B-U+000C, U+000E-U+001F.

### UTF-8 BOM

Removed by default. `--allow-utf8-bom` keeps the BOM while still fixing everything else in the file.

## Reported, Never Modified

### Emoji

Emoji are legitimate content in Markdown-like files (`.md`, `.markdown`, `.mdx`, `.mdc`, `.adoc`, `.asciidoc`, `.rst`)
and are left untouched there. In every other file they are reported as non-ASCII findings. Emoji are never rewritten.

### Encoding Problems

- UTF-16 LE/BE, with or without a BOM (`convert to UTF-8`).
- Invalid UTF-8 bytes.
- Mojibake -- double-encoded UTF-8 (for example `U+00C3 U+00A9` where an e-acute was meant). This short-circuits all
  other checks so that character-level fixes cannot corrupt the file further; repair it by re-encoding.
- Decomposed characters -- NFD combining marks (U+0300-U+036F), reported with a `normalize to NFC` hint.
- Any other non-ASCII byte that remains after the fixable issues are resolved.

### Working-Tree State

None of these is a character-level fix, so all are report-only:

- **Merge conflict markers** -- lines beginning with the seven-character sequences `<`, `|`, `=`, or `>` left after an
  unresolved merge. Reported only when both an opening and a closing marker are present, so a lone setext heading
  underline is not flagged, and a run longer than seven characters (a decorative separator) is ignored.
- **Git LFS pointers** -- a file whose working-tree content is still an LFS pointer (it begins with
  `version https://git-lfs.github.com/spec/`) because the real object was never checked out; run `git lfs pull`.
- **Broken symlinks** -- a symlink whose target does not exist. Valid symlinks are skipped and never followed, so fix
  mode can never rewrite a target outside the workspace.

## Skipped

Binary files, common binary extensions (`.png`, `.zip`, `.exe`, ...), and directory entries such as submodule gitlinks
are silently skipped.
