# Contributing to Plainify

## Design

| File                            | Responsibility                                                                                    |
| ------------------------------- | ------------------------------------------------------------------------------------------------- |
| `main.go`                       | CLI entry point: flag parsing, file discovery via `git ls-files`, JSON output.                    |
| `internal/plainify/plainify.go` | Core scanner: encoding detection, CRLF, typographic/invisible normalisation, working-tree checks. |
| `internal/plainify/emoji.go`    | Emoji classification (Unicode ranges) that lets Markdown-like files keep emoji.                   |

`internal/plainify` has no external dependencies, and the only subprocess call is `git ls-files` in `main.go` for file
discovery; all file I/O runs directly through `plainify.ScanFile`. Keep both invariants when adding checks.

Working-tree checks (merge conflict markers, Git LFS pointers, broken symlinks) are report-only and never modify a file.
Symlinks are inspected with `os.Lstat` and never followed, so fix mode cannot rewrite a target outside the workspace;
directory entries such as submodule gitlinks are skipped.

## Development Setup

Requires Go 1.24 or later. No external dependencies.

```bash
git clone https://github.com/goeselt/plainify.git
cd plainify
make build
```

## Local Verification

Run the same checks as CI (`gofmt`, `go vet`, `go test -race`) before opening a PR:

```bash
make check
```

Lint with the `pedant` container from the project root:

```bash
docker pull ghcr.io/goeselt/pedant:latest
docker run --rm -v "$(pwd):/work" ghcr.io/goeselt/pedant:latest
```

Source files, tests, and docs must all pass `plainify` itself: keep non-ASCII characters out of Go source (use `\uXXXX`
escapes in tests) and out of Markdown (use `U+XXXX` prose notation) so the repository stays clean under its own tool.

## Submitting Changes

Commit messages and PR titles must follow [Conventional Commits](https://www.conventionalcommits.org/). The release
pipeline derives the next version from the PR title.
