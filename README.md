# plainify

A command-line tool that detects and fixes common text encoding problems in a repository: CRLF line endings, non-ASCII
typographic characters, invisible characters, bidirectional control characters, and stray control characters. Emoji are
allowed in Markdown-like files and reported everywhere else.

It discovers files automatically via `git ls-files` and works equally well as a local tool and in CI pipelines. Output
is human-readable on stderr and machine-readable JSON on stdout.

## Installation

### Download a Release Binary

Grab the latest binary for your platform from the [Releases](https://github.com/goeselt/plainify/releases) page and put
it on your `PATH`.

### Build From Source

```bash
git clone https://github.com/goeselt/plainify.git
cd plainify
go build -o plainify .
```

Requires Go 1.24 or later. No external dependencies.

## What It Fixes

- **CRLF line endings** (`\r\n`) -- converted to LF; mixed line endings (both CRLF and LF in the same file) are detected
  specifically
- **Typographic characters** that sneak in via AI-generated text or word-processor paste -- em/en dash and Unicode
  hyphens (`\u2014` `\u2013` `\u2010`-`\u2012` `\u2015`), minus sign (`\u2212`), smart quotes, low quotes, and
  guillemets (`\u2018` `\u2019` `\u201A`-`\u201F` `\u00AB` `\u00BB` `\u2039` `\u203A`), primes (`\u2032`
  `\u2033`), arrows (`\u2192` `\u2190` `\u21D2`), Unicode spaces (`\u00A0`, `\u2000`-`\u200A`, `\u202F`,
  `\u205F`, `\u3000`), line/paragraph separators (`\u2028` `\u2029`), fullwidth ASCII variants
  (`\uFF01`-`\uFF5E`), ellipsis (`\u2026`), bullet (`\u2022`), box-drawing characters (`\u2514` `\u251C`
  `\u2500` `\u2502`) -- each replaced with its ASCII equivalent
- **Invisible characters** -- zero-width space (`\u200B`), zero-width non-joiner (`\u200C`), zero-width joiner
  (`\u200D`), soft hyphen (`\u00AD`), word joiner (`\u2060`), zero-width no-break space (`\uFEFF`), Mongolian
  vowel separator (`\u180E`), invisible mathematical operators (`\u2061`-`\u2064`), variation selectors
  (`\uFE00`-`\uFE0D`), and Unicode tag characters (`\uE0000`-`\uE007F`, a known data-smuggling channel) --
  deleted; these are invisible in editors but silently break string comparisons and regular expression matches
- **Bidirectional control characters** -- left/right-to-right marks, embedding, override, and isolate characters
  (`\u200E` `\u200F` `\u202A`-`\u202E` `\u2066`-`\u2069` `\u061C`) -- deleted; these are the basis of the
  [Trojan Source](https://trojansource.codes) attack (CVE-2021-42574), where code looks different in an editor than what
  the compiler sees
- **Stray control characters** -- C0 controls (`0x01`-`0x08`, `0x0B`-`0x0C`, `0x0E`-`0x1F`) including form feed and
  vertical tab -- deleted; these are almost never intentional in text files and break many tools
- **Emoji** (never rewritten) -- allowed in Markdown-like files (`.md`, `.markdown`, `.mdx`, `.mdc`, `.adoc`,
  `.asciidoc`, `.rst`), where they are often intentional content (documentation, agent instruction files); reported as
  non-ASCII findings in all other files
- **UTF-8 BOM** -- removed automatically in fix mode (suppress with `--allow-utf8-bom`)
- **Encoding issues** (reported, not auto-fixed) -- UTF-16 LE/BE with or without BOM, mojibake (double-encoded UTF-8,
  e.g. `U+00C3 U+00A9` where an e-acute was meant; reported for re-encoding and deliberately never character-fixed),
  decomposed characters (NFD combining marks, reported with a normalize-to-NFC hint), and arbitrary non-ASCII bytes
  that remain after all fixable issues are resolved

### What It Reports (Working-Tree State)

These are reported but never modified -- none of them is a character-level fix:

- **Merge conflict markers** -- lines beginning with `<<<<<<<`, `|||||||`, `=======`, or `>>>>>>>` left in a file after
  an unresolved merge; reported only when both an opening and a closing marker are present, so a lone `=======` setext
  heading is not flagged
- **Git LFS pointers** -- a file whose working-tree content is still an LFS pointer (`version
  https://git-lfs.github.com/spec/...`) because the real object was never checked out; run `git lfs pull`
- **Broken symlinks** -- a symlink whose target does not exist; valid symlinks are skipped and never followed

Binary files, common binary extensions (`.png`, `.zip`, `.exe`, ...), and directory entries such as submodule gitlinks
are silently skipped.

## Usage

```bash
plainify [options] [path...]
```

With no paths, `plainify` discovers files automatically using `git ls-files` (tracked and untracked non-ignored files).
Pass explicit paths to check only those files.

### Options

| Flag               | Description                                                  |
| ------------------ | ------------------------------------------------------------ |
| `--nofix`, `-n`    | Report issues without modifying files                        |
| `--workspace path` | Repository root for `git ls-files` and relative path display |
| `--exclude regex`  | Skip files matching the regular expression (repeatable)      |
| `--allow-utf8-bom` | Do not flag UTF-8 BOM as an issue                            |
| `-q`               | Suppress human-readable progress; only emit JSON             |
| `--version`        | Print version and exit                                       |

### Exit Codes

| Code | Meaning                                            |
| ---- | -------------------------------------------------- |
| `0`  | No issues found (or all issues fixed)              |
| `1`  | Findings remain after the run                      |
| `2`  | Runtime error (bad arguments, Git not found, etc.) |

## Examples

```bash
# Fix everything in the current Git repository (default)
plainify

# Check only, do not modify files
plainify --nofix

# Check a specific directory
plainify --nofix path/to/repo

# Check specific files
plainify --nofix docs/guide.md src/main.go

# Exclude generated and vendored paths
plainify --exclude "vendor|generated|\.pb\.go$"

# Suppress human-readable output (useful in scripts)
plainify -q | jq .
```

## Output

Human-readable progress is written to **stderr**:

```text
[plainify] checking 42 file(s)...
[plainify] 2 finding(s)
  docs/guide.md:12:3 non-ASCII typographic character U+2014 - use ASCII equivalent
  README.md:8:1 CRLF line endings - convert to LF
```

JSON is written to **stdout** (always, regardless of `-q`):

```json
{
  "status": "fail",
  "findings_count": 2,
  "findings": [
    {
      "file": "docs/guide.md",
      "line": 12,
      "col": 3,
      "message": "non-ASCII typographic character U+2014 - use ASCII equivalent"
    },
    {
      "file": "README.md",
      "line": 8,
      "message": "CRLF line endings - convert to LF"
    }
  ]
}
```

## Use in CI

```yaml
- name: Run plainify
  run: plainify --nofix
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [LICENSE](LICENSE).
