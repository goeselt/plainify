# Contributing to Plainify

## Design

| File                                    | Responsibility                                                                     |
| --------------------------------------- | ---------------------------------------------------------------------------------- |
| `main.go`                               | CLI entry point: flag parsing, file discovery via `git ls-files`, JSON output.     |
| `internal/plainify/plainify.go`         | Core scanner: encoding detection, CRLF, typographic character and invisible character normalisation. |
| `internal/plainify/emoji.go`            | Emoji detection and GitHub shortcode replacement for `.md` files.                  |

`internal/plainify` has no external dependencies. The only subprocess call is in `main.go` via `exec.Command("git", "ls-files", ...)` for automatic file discovery; all file I/O is handled directly by `plainify.ScanFile`.

## Development Setup

Go 1.24 or later. No external dependencies.

```bash
go build ./...
```

## Local Verification

Format:

```bash
gofmt -l .
```

Vet:

```bash
go vet ./...
```

Test:

```bash
go test -race ./...
```

Lint:

```bash
docker pull ghcr.io/goeselt/pedant:latest
docker run --rm -v "$(pwd):/work" ghcr.io/goeselt/pedant:latest
```

## Submitting Changes

Commit messages and PR titles must follow [Conventional Commits](https://www.conventionalcommits.org/). The release
pipeline uses the PR title to determine the next version.
