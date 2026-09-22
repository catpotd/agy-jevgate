# agy-jevgate

`agy-jevgate` is a fail-closed `PreToolUse` hook for Antigravity shell commands. It checks `run_command` requests before Antigravity executes them.

The hook uses three decisions:

- A small list of exact read-only commands is allowed without a network request.
- A short static guard blocks common destructive command forms.
- Other commands are scored by TypeSafe Jev.

Missing credentials, invalid configuration, invalid hook input, Jev errors, and unreadable safety state all produce `deny`.

This project is not a sandbox. It does not intercept tools other than the configured `run_command` hook, and it cannot prove what an arbitrary script will do. Keep normal operating-system permissions and repository protections in place.

## Requirements

- Antigravity CLI (`agy`) with `PreToolUse` hooks
- Python 3.9 or newer
- A POSIX-like operating system with `fcntl` file locking
- A TypeSafe AI API key for commands that are not exact fast passes
- macOS for the built-in Keychain integration

On POSIX-like systems other than macOS, configure `apiKeyCommand` in the optional configuration file. Windows is not supported by the file-locking implementation.

## Installation

Install the plugin globally:

```bash
mkdir -p ~/.gemini/config/plugins
git clone https://github.com/catpotd/agy-jevgate.git ~/.gemini/config/plugins/agy-jevgate
```

Or install it for one project:

```bash
mkdir -p .agents/plugins
git clone https://github.com/catpotd/agy-jevgate.git .agents/plugins/agy-jevgate
```

## Setup

On macOS, store the API key in Keychain:

```bash
python3 ~/.gemini/config/plugins/agy-jevgate/scripts/setup.py
```

The setup command does not create a plaintext key file or an environment variable. Check or remove the stored key with:

```bash
python3 ~/.gemini/config/plugins/agy-jevgate/scripts/setup.py --check
python3 ~/.gemini/config/plugins/agy-jevgate/scripts/setup.py --delete
```

For an external secret manager, create `~/.config/agy-jevgate/config.json`:

```json
{
  "apiKeyCommand": "op read op://vault/typesafe/credential",
  "threshold": 0.8
}
```

`apiKeyCommand` is split into an executable and arguments without shell expansion. Shell operators such as `&&` are not executed.

`threshold` must be a finite number from `0` through `1`. A Jev probability at or above this value is denied.

## Decision flow

1. The hook validates the JSON payload and reads the persistent denied-command record.
2. An exact command in the same `conversationId` is denied again.
3. Exact read-only fast passes are allowed.
4. Static dangerous forms are denied and recorded.
5. Remaining commands are sent to Jev.
6. A high-risk result, API error, missing key, or safety-state error is denied and recorded.

The denied record is stored at `~/.config/agy-jevgate/denied_commands.json`. Entries do not expire. The hook keys entries by the exact command string and `conversationId`.

There is no chat-based approval path. A user message cannot authorize a command that this hook denied. Do not retry a denied command or replace it with a workaround in the same agent session. If the user approves the operation, they must perform it outside the plugin-controlled agent session.

A changed command or a different `conversationId` is a new request and is evaluated again. This does not make the plugin a complete authorization system.

The static guard is intentionally short and conservative. Its patterns are a supplementary pre-check, not a complete shell parser or a list of every dangerous command.

## Development

Run the test suite:

```bash
python3 -m unittest discover -s tests
```

Validate the plugin manifest with the Antigravity CLI:

```bash
agy plugin validate .
```

The project uses only Python's standard library at runtime.

## License

MIT License. See [LICENSE](LICENSE).
