#!/usr/bin/env python3
"""Antigravity PreToolUse hook for command safety evaluation via TypeSafe Jev."""

import datetime
import fcntl
import json
import math
import os
import platform
import re
import shlex
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

DEFAULT_THRESHOLD = 0.8
KEYCHAIN_SERVICE = "agy-jevgate"
KEYCHAIN_ACCOUNT = "api_key"
CONFIG_PATH = os.path.expanduser("~/.config/agy-jevgate/config.json")
GATE_LOG_PATH = os.path.expanduser("~/.config/agy-jevgate/gate.log")
DENIED_COMMANDS_PATH = os.path.expanduser("~/.config/agy-jevgate/denied_commands.json")
DENIED_COMMANDS_LOCK_PATH = os.path.expanduser("~/.config/agy-jevgate/denied_commands.lock")
API_ENDPOINT = "https://api.typesafe.ai/v1/systemone"
MAX_DENIED_COMMANDS_BYTES = 1024 * 1024

FAST_PASS_COMMANDS = frozenset({
    "git status",
    "git diff",
    "git log",
    "git branch",
    "git show",
    "gh pr list",
    "gh pr view",
    "gh pr status",
    "gh pr diff",
    "gh pr checks",
    "ls",
    "pwd",
})

STATIC_DANGEROUS_PATTERNS = [
    r"(^|[;&|]|\bdo|\bthen)\s*rm\s+.*(-[a-zA-Z0-9]*[rR][a-zA-Z0-9]*|--recursive)\b",
    r"(^|[;&|]|\bdo|\bthen)\s*rm\s+.*--no-preserve-root\b",
    r"(^|[;&|]|\bdo|\bthen)\s*git\s+push\s+.*(-f\b|--force\b|\+[a-zA-Z0-9_\-\./]+)",
    r"(^|[;&|]|\bdo|\bthen)\s*git\s+reset\s+--hard\b",
    r"(^|[;&|]|\bdo|\bthen)\s*(dropdb|createdb|mkfs)\b",
    r"(^|[;&|]|\bdo|\bthen)\s*dd\s+if=",
    r"\b(DROP\s+DATABASE|DROP\s+TABLE|TRUNCATE\s+TABLE|TRUNCATE\b|DELETE\s+FROM)\b",
]


def log_decision(decision, stage, cmd, reason=""):
    try:
        os.makedirs(os.path.dirname(GATE_LOG_PATH), exist_ok=True)
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_line = f"[{timestamp}] DECISION={decision.upper()} STAGE={stage} CMD={cmd!r}"
        if reason:
            log_line += f" REASON={reason!r}"
        with open(GATE_LOG_PATH, "a", encoding="utf-8") as log_file:
            log_file.write(log_line + "\n")
    except OSError:
        # Logging is advisory and must not turn an existing deny into an allow.
        return


def load_config():
    if not os.path.isfile(CONFIG_PATH):
        return {}, None
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as config_file:
            config = json.load(config_file)
    except (OSError, json.JSONDecodeError) as error:
        return None, f"Cannot read config: {type(error).__name__}"
    if not isinstance(config, dict):
        return None, "Config must be a JSON object"
    return config, None


def get_threshold(config):
    threshold = config.get("threshold", DEFAULT_THRESHOLD)
    if isinstance(threshold, bool) or not isinstance(threshold, (int, float)):
        return None, "threshold must be a number between 0 and 1"
    threshold = float(threshold)
    if not math.isfinite(threshold) or not 0 <= threshold <= 1:
        return None, "threshold must be a number between 0 and 1"
    return threshold, None


def _load_denied_commands_unlocked():
    if not os.path.exists(DENIED_COMMANDS_PATH):
        return {}
    if os.path.getsize(DENIED_COMMANDS_PATH) > MAX_DENIED_COMMANDS_BYTES:
        raise ValueError("Denied command record exceeded its size limit")
    with open(DENIED_COMMANDS_PATH, "r", encoding="utf-8") as denied_commands_file:
        denied_commands_by_conversation = json.load(denied_commands_file)
    if not isinstance(denied_commands_by_conversation, dict):
        raise ValueError("Denied command record must be a JSON object")
    if denied_commands_by_conversation.get("blocked") is True:
        raise ValueError("Denied command record reached its capacity limit")
    for conversation_id, commands in denied_commands_by_conversation.items():
        if not isinstance(conversation_id, str):
            raise ValueError("Denied command record contains a non-string conversation ID")
        if not isinstance(commands, list) or not all(isinstance(command, str) for command in commands):
            raise ValueError("Denied command record contains invalid commands")
    return denied_commands_by_conversation


def read_denied_commands():
    try:
        state_directory = os.path.dirname(DENIED_COMMANDS_PATH)
        os.makedirs(state_directory, exist_ok=True)
        with open(DENIED_COMMANDS_LOCK_PATH, "a+", encoding="utf-8") as lock_file:
            fcntl.flock(lock_file, fcntl.LOCK_SH)
            try:
                return _load_denied_commands_unlocked(), None
            finally:
                fcntl.flock(lock_file, fcntl.LOCK_UN)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        return None, f"Cannot read denied command record: {type(error).__name__}"


def is_denied_command(cmd, conversation_id):
    denied_commands_by_conversation, error = read_denied_commands()
    if error:
        return None, error
    return cmd in denied_commands_by_conversation.get(conversation_id, []), None


def _replace_denied_commands_unlocked(denied_commands_by_conversation):
    state_directory = os.path.dirname(DENIED_COMMANDS_PATH)
    file_descriptor, temporary_path = tempfile.mkstemp(
        dir=state_directory,
        prefix=".denied_commands.",
    )
    try:
        with os.fdopen(file_descriptor, "w", encoding="utf-8") as temporary_file:
            json.dump(denied_commands_by_conversation, temporary_file, indent=2)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.replace(temporary_path, DENIED_COMMANDS_PATH)
    finally:
        if os.path.exists(temporary_path):
            os.unlink(temporary_path)


def record_denied_command(cmd, conversation_id):
    try:
        state_directory = os.path.dirname(DENIED_COMMANDS_PATH)
        os.makedirs(state_directory, exist_ok=True)
        with open(DENIED_COMMANDS_LOCK_PATH, "a+", encoding="utf-8") as lock_file:
            fcntl.flock(lock_file, fcntl.LOCK_EX)
            try:
                denied_commands_by_conversation = _load_denied_commands_unlocked()
                commands = denied_commands_by_conversation.setdefault(conversation_id, [])
                if cmd not in commands:
                    commands.append(cmd)
                    serialized_size = len(json.dumps(denied_commands_by_conversation).encode("utf-8"))
                    if serialized_size > MAX_DENIED_COMMANDS_BYTES:
                        _replace_denied_commands_unlocked({"blocked": True})
                        return False, "Denied command record reached its capacity limit"
                    _replace_denied_commands_unlocked(denied_commands_by_conversation)
            finally:
                fcntl.flock(lock_file, fcntl.LOCK_UN)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        return False, f"Cannot record denied command: {type(error).__name__}"
    return True, None


def get_api_key(config):
    api_key_command = config.get("apiKeyCommand")
    if isinstance(api_key_command, str) and api_key_command:
        try:
            command_args = shlex.split(api_key_command)
            if not command_args:
                return ""
            result = subprocess.run(
                command_args,
                shell=False,
                capture_output=True,
                text=True,
                timeout=1.5,
                check=True,
            )
            api_key = result.stdout.strip()
            if api_key:
                return api_key
        except (OSError, ValueError, subprocess.SubprocessError):
            return ""

    if platform.system() == "Darwin":
        command = [
            "security",
            "find-generic-password",
            "-s", KEYCHAIN_SERVICE,
            "-a", KEYCHAIN_ACCOUNT,
            "-w",
        ]
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=1.5, check=True)
            api_key = result.stdout.strip()
            if api_key:
                return api_key
        except (OSError, subprocess.SubprocessError):
            return ""

    return ""


def is_fast_pass(cmd):
    return cmd in FAST_PASS_COMMANDS


def is_static_dangerous(cmd):
    return any(re.search(pattern, cmd, re.IGNORECASE) for pattern in STATIC_DANGEROUS_PATTERNS)


def make_allow_response(cmd):
    response = {"decision": "allow"}
    if cmd:
        response["permissionOverrides"] = [f"command({cmd})"]
    return response


def make_deny_response(cmd, reason):
    command_detail = f" for command '{cmd}'" if cmd else ""
    return {
        "decision": "deny",
        "reason": (
            f"[SAFETY GATE INTERVENTION] Blocked{command_detail}: {reason}. "
            "Do not retry or substitute this command. This plugin cannot authorize commands from chat. "
            "Tell the user the command and reason. The user must perform any approved operation outside this plugin-controlled agent session."
        ),
    }


def deny_and_record(cmd, conversation_id, stage, reason):
    recorded, record_error = record_denied_command(cmd, conversation_id)
    if not recorded:
        reason = f"{reason}; {record_error}"
    log_decision("deny", stage, cmd, reason)
    return make_deny_response(cmd, reason)


def evaluate_with_jev(cmd, api_key, threshold, conversation_id):
    request_data = {
        "model": "jev-latest",
        "state": {"command": cmd},
        "questions": {
            "is_dangerous": {
                "type": "noul",
                "instructions": "Evaluate whether the shell command in `state.command` is dangerous, destructive, or modifies repository state outside temporary directories.",
            }
        },
    }
    request = urllib.request.Request(
        API_ENDPOINT,
        data=json.dumps(request_data).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=2.0) as response:
            body = json.loads(response.read().decode("utf-8"))
        probability = body.get("answers", {}).get("is_dangerous", {}).get("noul")
        if isinstance(probability, bool) or not isinstance(probability, (int, float)):
            return deny_and_record(cmd, conversation_id, "jev_error", "Jev response has an invalid noul probability")
        probability = float(probability)
        if not math.isfinite(probability) or not 0 <= probability <= 1:
            return deny_and_record(cmd, conversation_id, "jev_error", "Jev response has an invalid noul probability")
        stage = f"jev_ai(noul={probability:.2f})"
        if probability >= threshold:
            return deny_and_record(cmd, conversation_id, stage, f"Jev detected risk probability: {probability:.2f}")
        log_decision("allow", stage, cmd)
        return make_allow_response(cmd)
    except urllib.error.HTTPError as error:
        return deny_and_record(cmd, conversation_id, "jev_http_error", f"Jev API returned HTTP {error.code}")
    except (OSError, ValueError, json.JSONDecodeError) as error:
        return deny_and_record(
            cmd,
            conversation_id,
            "jev_connection_error",
            f"Jev API connection failed: {type(error).__name__}",
        )


def main():
    cmd = ""
    try:
        payload = json.load(sys.stdin)
        if not isinstance(payload, dict):
            print(json.dumps(make_deny_response(cmd, "Hook payload must be a JSON object")))
            return
        tool_call = payload.get("toolCall")
        if (
            not isinstance(tool_call, dict)
            or tool_call.get("name") != "run_command"
            or not isinstance(tool_call.get("args"), dict)
        ):
            print(json.dumps(make_deny_response(cmd, "Hook payload must describe run_command with args")))
            return
        command_line = tool_call["args"].get("CommandLine")
        if not isinstance(command_line, str):
            print(json.dumps(make_deny_response(cmd, "CommandLine must be a string")))
            return
        cmd = command_line
        conversation_id = payload.get("conversationId", "")
        if not isinstance(conversation_id, str) or not conversation_id:
            print(json.dumps(make_deny_response(cmd, "conversationId must be a non-empty string")))
            return
        if not cmd.strip():
            print(json.dumps(make_deny_response(cmd, "CommandLine must not be empty")))
            return

        is_denied, denied_record_error = is_denied_command(cmd, conversation_id)
        if denied_record_error:
            print(json.dumps(make_deny_response(cmd, denied_record_error)))
            return
        if is_denied:
            reason = "This command was denied earlier in this conversation"
            log_decision("deny", "denied_command", cmd, reason)
            print(json.dumps(make_deny_response(cmd, reason)))
            return

        config, config_error = load_config()
        if config_error:
            print(json.dumps(make_deny_response(cmd, config_error)))
            return
        threshold, threshold_error = get_threshold(config)
        if threshold_error:
            print(json.dumps(make_deny_response(cmd, threshold_error)))
            return
        if is_fast_pass(cmd):
            log_decision("allow", "fast_pass", cmd)
            print(json.dumps(make_allow_response(cmd)))
            return
        if is_static_dangerous(cmd):
            response = deny_and_record(
                cmd,
                conversation_id,
                "static_guard",
                f"Dangerous command pattern detected: {cmd}",
            )
            print(json.dumps(response))
            return
        api_key = get_api_key(config)
        if not api_key:
            response = deny_and_record(
                cmd,
                conversation_id,
                "missing_key",
                "TypeSafe API key not configured in Keychain or config.json",
            )
            print(json.dumps(response))
            return
        print(json.dumps(evaluate_with_jev(cmd, api_key, threshold, conversation_id)))
    except Exception as error:
        log_decision("deny", "hook_error", cmd, type(error).__name__)
        print(json.dumps(make_deny_response(cmd, f"Hook execution failed: {type(error).__name__}")))


if __name__ == "__main__":
    main()
