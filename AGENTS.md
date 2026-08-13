# AGENTS.md

This file records repository-specific conventions and maintainer preferences for AI agents.
Do not restate general software-engineering guidance here.

## Project

- `dpass` is a Go CLI built with Cobra.
- The module path is `github.com/rbee3u/dpass`.
- `main.go` wires the root command and subcommands.
- `cmd/` contains CLI commands; `pkg/` contains reusable packages.
- `Makefile`, `go.mod`, `.golangci.yml`, and CI workflows are the sources of truth for commands, versions, and tool configuration.

## Repository Conventions

- Keep repository-authored content in English, including identifiers, comments, documentation, CLI text, errors, logs, and test descriptions.
- Put Cobra command construction and execution logic in `cmd/<name>/backend.go`.
- Put domain-specific errors in `errors.go` when a command or package needs them.
- Preserve injectable `io.Reader` and `io.Writer` boundaries in CLI backends; use `pkg/testx` helpers in command tests where appropriate.
- Keep `cmd/` tests in the implementation package when they need command internals.
- Prefer external test packages for `pkg/`; use `export_test.go` only when tests require access to unexported behavior.
- Preserve structured error behavior and compatibility with `errors.Is` and `errors.As`.
- Treat cryptography, mnemonics, key derivation, and encoding as compatibility-sensitive. Preserve established vectors and external output formats unless a requirement explicitly changes them.
- Prefer the standard library and existing dependencies. A new third-party dependency should have a clear benefit, active maintenance, and compatibility with the existing toolchain.

## Change Boundaries

- Ask for confirmation before destructive operations, architectural changes, broad migrations, or other high-risk behavior changes.
- Ordinary scoped changes, including changes across multiple files, do not require separate approval.
- Keep edits limited to the requested behavior and directly related consistency work.

## Validation

- For Go source or test changes, run these commands in order:
  1. `make format`
  2. `make build`
  3. `make test`
  4. `make lint`
- For documentation-only changes, inspect the final diff and run `git diff --check`; do not run unrelated Go checks.
- For configuration, workflow, release, or other changes, run the checks directly relevant to the affected behavior.
- Report which checks actually ran, their results, and any relevant checks that were skipped.
