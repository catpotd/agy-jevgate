# Contributing to agy-jevgate

## Before you start

Search existing issues before opening a new one. For security concerns, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

## Development environment

- Python 3.9 or newer
- Antigravity CLI (`agy`) for manifest validation
- macOS only for testing the Keychain setup path

The runtime uses only Python's standard library.

## Change process

1. Open an issue when the change affects behavior or public configuration.
2. Create a branch with a full-word prefix such as `feature/` or `fix/`.
3. Keep the change focused and update documentation when behavior changes.
4. Add or update tests for the behavior you change.
5. Run the test suite and plugin validation locally.
6. Open a pull request with the included template.

Run the local checks with:

```bash
python3 -m unittest discover -s tests
agy plugin validate .
```

Do not include API keys, command transcripts, or personal data in commits or issue reports.

## Commit messages

Use a short prefix and explain the purpose of the change, for example:

```text
fix: deny malformed hook payloads
```

Do not include credentials or URLs in commit messages.

## Pull requests

Describe the user-visible behavior, the safety impact, and the checks you ran. Keep unrelated formatting changes out of the pull request.
