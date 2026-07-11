# plainify

A command-line tool that normalizes repository text to plain, portable ASCII -- and flags the dangerous invisible
characters you cannot see in an editor.

Text files accumulate cruft that looks fine but is not: smart quotes and em-dashes from AI output or word-processor
paste, `\r\n` from cross-platform edits, zero-width and bidirectional characters that are invisible on screen but change
what compilers and regexes see, emoji in source files, and mojibake from a bad re-encoding. `plainify` rewrites what it
can safely fix in place and reports the rest, so diffs stay clean and "why does this regular expression not match?"
mysteries go away.

- **Fixes in place, or previews.** A plain run rewrites every fixable issue; `--nofix` reports without touching a byte.
- **Catches invisible attacks.** Bidirectional controls (the [Trojan Source](https://trojansource.codes) vector,
  CVE-2021-42574), zero-width characters, and Unicode tag characters -- invisible in editors, dangerous in code and in
  agent instruction files.
- **Knows where emoji belong.** Left intact in Markdown and agent-instruction files, flagged in source code.
- **Machine- and human-readable.** Human-readable progress on stderr, structured JSON on stdout for CI gating.
- **Zero config, git-aware.** Discovers files through `git ls-files` -- no config file, no external dependencies.

Reach for `plainify` when a diff shows changes you cannot see, a regular expression mysteriously fails to match, or you
want CI to reject non-portable text before it lands.

> [!NOTE]
>
> A plain run rewrites fixable issues **in place**. Run with `--nofix` first to preview, or let version control be your
> safety net.

## Getting Started

### Install

Grab the latest binary for your platform from the [Releases](https://github.com/goeselt/plainify/releases) page and put
it on your `PATH`, or install with Go (1.24+):

```bash
go install github.com/goeselt/plainify@latest
```

### Try It

Preview what a repository contains without changing anything:

```text
$ plainify --nofix
[plainify] checking 128 file(s)...
[plainify] 3 finding(s)
  docs/guide.md:14:22 non-ASCII typographic character U+2019 - use ASCII equivalent
  internal/auth.go:1:9 bidirectional control character U+202E (right-to-left override) - remove (Trojan Source risk)
  notes.txt:5:9 zero-width character U+200B (zero-width space) - remove
```

Drop `--nofix` and `plainify` fixes what it safely can in place, leaving only issues that need a human:

```text
$ plainify
[plainify] checking 128 file(s)...
[plainify] pass
```

## What It Checks

**Fixed in place** (rewritten unless `--nofix`):

- **Line endings** -- CRLF and mixed CRLF/LF converted to LF.
- **Typographic characters** -- smart quotes, dashes, guillemets, primes, arrows, Unicode spaces, fullwidth ASCII, and
  more, each replaced with its ASCII equivalent.
- **Invisible characters** -- zero-width spaces, word joiners, variation selectors, and Unicode tag characters removed.
- **Bidirectional controls** -- Trojan Source (CVE-2021-42574) attack vectors removed.
- **Stray control characters** -- C0 controls (form feed, vertical tab, ...) removed.
- **UTF-8 BOM** -- removed by default; keep it with `--allow-utf8-bom`.

**Reported, never modified:**

- **Emoji** outside Markdown-like files.
- **Encoding problems** -- UTF-16, invalid UTF-8, mojibake, and NFD (decomposed) characters.
- **Merge conflict markers** left in a file after an unresolved merge.
- **Git LFS pointers** whose object was never checked out.
- **Broken symlinks** (valid symlinks are skipped and never followed).

See [docs/checks.md](docs/checks.md) for the exact character set and the behavior of every check. Binary files, known
binary extensions, and submodule gitlinks are silently skipped.

## Usage

```bash
plainify [options] [path...]
```

With no paths, `plainify` discovers files via `git ls-files` (tracked and untracked, non-ignored). Pass explicit paths
to check only those files.

| Flag               | Description                                                  |
| ------------------ | ------------------------------------------------------------ |
| `--nofix`, `-n`    | Report issues without modifying files                        |
| `--workspace path` | Repository root for `git ls-files` and relative path display |
| `--exclude regex`  | Skip files matching the regular expression (repeatable)      |
| `--allow-utf8-bom` | Do not flag or remove a UTF-8 BOM                            |
| `-q`               | Suppress human-readable progress; only emit JSON             |
| `--version`        | Print version and exit                                       |

```bash
# Fix everything in the current Git repository (default)
plainify

# Preview without modifying files
plainify --nofix

# Check specific paths
plainify --nofix docs/guide.md src/main.go

# Exclude generated and vendored paths
plainify --exclude "vendor|generated|\.pb\.go$"
```

| Exit code | Meaning                                            |
| --------- | -------------------------------------------------- |
| `0`       | No issues found (or all issues fixed)              |
| `1`       | Findings remain after the run                      |
| `2`       | Runtime error (bad arguments, Git not found, etc.) |

## Output

Human-readable progress goes to **stderr**; structured JSON always goes to **stdout** (even with `-q`), so it pipes
cleanly into `jq` or a CI step:

```json
{
  "status": "fail",
  "findings_count": 1,
  "findings": [
    {
      "file": "docs/guide.md",
      "line": 12,
      "col": 3,
      "message": "non-ASCII typographic character U+2014 - use ASCII equivalent"
    }
  ]
}
```

In CI, run in report-only mode to fail the job on any finding:

```yaml
- name: Run plainify
  run: plainify --nofix
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [LICENSE](LICENSE).
