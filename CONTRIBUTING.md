# Contributing to Vexil

We welcome robust, high-quality contributions. To maintain the integrity and focus of Vexil, please adhere to the following workflow and standards.

## Development Workflow

1. **Security First**: All changes must be evaluated against their security implications. We do not merge code that introduces risk or weakens the detection threshold.
2. **Single Responsibility Branches**: One feature or bug fix per branch. Do not mix unrelated changes.
3. **Pull Requests**: Do not commit directly to the main branch. Always create a Pull Request detailing the changes, motivation, and verification steps.

## Coding Standards

- **Effective Go**: Write idiomatic Go. Read and follow [Effective Go](https://go.dev/doc/effective_go).
- **Conciseness**: Avoid verborragic comments. Code must be self-documenting as much as possible. Comments should explain *why*, not *what*.
- **No Emojis**: Maintain a strictly professional and austere aesthetic in commit messages, documentation, and the code itself.

## Commit Messages

Use standard conventional commit prefixes with clear, direct explanations:
- `feat:` for new capabilities.
- `fix:` for bug resolution.
- `docs:` for documentation updates.
- `refactor:` for code restructurings that do not alter behavior.

## Testing

- **100% Passing Tests**: Ensure `go test -v ./...` passes without errors.
- **Crypto & Unit Tests**: Any modifications to the entropy logic or pattern matching must be accompanied by mathematical or boundary-driven unit tests. No change will be accepted without coverage proving it does not inadvertently increase false positives.
