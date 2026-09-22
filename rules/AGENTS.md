# agy-jevgate safety rules

## Safety gate intervention

When a `run_command` call is denied by the safety gate:

1. Stop calling tools in the current agent turn.
2. Tell the user the exact command and the reason returned by the gate.
3. Do not retry the command, change its spelling, or use another tool to perform the same operation.
4. Do not treat a later chat message as authorization. The hook has no chat-based approval path.

If the user approves the operation, they must perform it outside the plugin-controlled agent session. These instructions supplement the hook and do not extend its interception scope to other tools.
