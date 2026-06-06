# plainify

A command-line tool that detects and fixes common text encoding problems in a repository: CRLF line endings, non-ASCII
typographic characters, invisible characters, bidirectional control characters, stray control characters, and emoji in
Markdown files.

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

Requires Go 1.26.4 or later. No external dependencies.

## What It Fixes

- **CRLF line endings** (`\r\n`) -- converted to LF; mixed line endings (both CRLF and LF in the same file) are detected
  specifically
- **Typographic characters** that sneak in via AI-generated text or word-processor paste -- em dash (`\u2014`), en dash
  (`\u2013`), smart quotes (`\u2018` `\u2019` `\u201C` `\u201D`), arrows (`\u2192` `\u2190` `\u21D2`), non-breaking
  space (`\u00A0`), ellipsis (`\u2026`), bullet (`\u2022`), box-drawing characters (`\u2514` `\u251C` `\u2500` `\u2502`)
  -- each replaced with its ASCII equivalent
- **Invisible characters** -- zero-width space (`\u200B`), zero-width non-joiner (`\u200C`), zero-width joiner
  (`\u200D`), soft hyphen (`\u00AD`) -- deleted; these are invisible in editors but silently break string comparisons
  and regular expression matches
- **Bidirectional control characters** -- left/right-to-right marks, embedding, override, and isolate characters
  (`\u200E` `\u200F` `\u202A`-`\u202E` `\u2066`-`\u2069` `\u061C`) -- deleted; these are the basis of the
  [Trojan Source](https://trojansource.codes) attack (CVE-2021-42574), where code looks different in an editor than what
  the compiler sees
- **Stray control characters** -- C0 controls (`0x01`-`0x08`, `0x0B`-`0x0C`, `0x0E`-`0x1F`) including form feed and
  vertical tab -- deleted; these are almost never intentional in text files and break many tools
- **Emoji in `.md` files** -- replaced with GitHub shortcode form (`:rocket:`, `:bug:`, ...)
- **UTF-8 BOM** -- removed automatically in fix mode (suppress with `--allow-utf8-bom`)
- **Encoding issues** (reported, not auto-fixed) -- UTF-16 LE/BE with or without BOM, arbitrary non-ASCII bytes that
  remain after all fixable issues are resolved

Binary files and common binary extensions (`.png`, `.zip`, `.exe`, ...) are silently skipped.

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
