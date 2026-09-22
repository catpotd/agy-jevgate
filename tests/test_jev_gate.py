"""Unit tests for the agy-jevgate command hook."""

import io
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts")))

import jev_gate


class TestJevGate(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        state_directory = self.temp_dir.name
        self.denied_commands_path = os.path.join(state_directory, "denied_commands.json")
        self.denied_commands_lock_path = os.path.join(state_directory, "denied_commands.lock")
        self.gate_log_path = os.path.join(state_directory, "gate.log")
        self.config_path = os.path.join(state_directory, "config.json")
        self.patches = [
            patch("jev_gate.DENIED_COMMANDS_PATH", self.denied_commands_path),
            patch("jev_gate.DENIED_COMMANDS_LOCK_PATH", self.denied_commands_lock_path),
            patch("jev_gate.GATE_LOG_PATH", self.gate_log_path),
            patch("jev_gate.CONFIG_PATH", self.config_path),
        ]
        for active_patch in self.patches:
            active_patch.start()

    def tearDown(self):
        for active_patch in reversed(self.patches):
            active_patch.stop()
        self.temp_dir.cleanup()

    def test_fast_pass_accepts_only_exact_read_only_commands(self):
        self.assertTrue(jev_gate.is_fast_pass("git status"))
        self.assertTrue(jev_gate.is_fast_pass("gh pr list"))
        self.assertTrue(jev_gate.is_fast_pass("pwd"))
        self.assertFalse(jev_gate.is_fast_pass("git status --short"))
        self.assertFalse(jev_gate.is_fast_pass("git add ."))
        self.assertFalse(jev_gate.is_fast_pass("git push origin main"))

    def test_static_guard_detects_common_destructive_forms(self):
        self.assertTrue(jev_gate.is_static_dangerous("rm -rf /tmp/data"))
        self.assertTrue(jev_gate.is_static_dangerous("git push origin main --force"))
        self.assertTrue(jev_gate.is_static_dangerous("git reset --hard HEAD~1"))
        self.assertTrue(jev_gate.is_static_dangerous("psql -c 'DROP TABLE users;'"))
        self.assertFalse(jev_gate.is_static_dangerous("rm -f report.txt"))
        self.assertFalse(jev_gate.is_static_dangerous("git status"))

    def test_denied_commands_are_exact_and_conversation_scoped(self):
        command = "rm -rf /tmp/data"
        recorded, error = jev_gate.record_denied_command(command, "conversation-a")

        self.assertTrue(recorded)
        self.assertIsNone(error)
        self.assertEqual(jev_gate.is_denied_command(command, "conversation-a"), (True, None))
        self.assertEqual(jev_gate.is_denied_command(command + " ", "conversation-a"), (False, None))
        self.assertEqual(jev_gate.is_denied_command(command, "conversation-b"), (False, None))

    def test_invalid_denied_state_fails_closed(self):
        with open(self.denied_commands_path, "w", encoding="utf-8") as denied_file:
            denied_file.write("not json")

        denied, error = jev_gate.is_denied_command("git push", "conversation-a")

        self.assertIsNone(denied)
        self.assertIsNotNone(error)

    @patch("jev_gate.urllib.request.urlopen")
    def test_evaluate_with_jev_allows_low_risk_command(self, mock_urlopen):
        response = MagicMock()
        response.read.return_value = json.dumps({
            "answers": {"is_dangerous": {"noul": 0.05}},
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = response

        result = jev_gate.evaluate_with_jev("python3 script.py", "fake-key", 0.8, "conversation-a")

        self.assertEqual(result["decision"], "allow")
        self.assertEqual(result["permissionOverrides"], ["command(python3 script.py)"])

    @patch("jev_gate.urllib.request.urlopen")
    def test_evaluate_with_jev_denies_and_records_high_risk_command(self, mock_urlopen):
        response = MagicMock()
        response.read.return_value = json.dumps({
            "answers": {"is_dangerous": {"noul": 0.95}},
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = response
        command = "python3 deploy.py --production"

        result = jev_gate.evaluate_with_jev(command, "fake-key", 0.8, "conversation-a")

        self.assertEqual(result["decision"], "deny")
        self.assertIn("0.95", result["reason"])
        self.assertEqual(jev_gate.is_denied_command(command, "conversation-a"), (True, None))

    def test_main_keeps_denial_after_user_message(self):
        command = "rm -rf /tmp/data"
        payload = {
            "conversationId": "conversation-a",
            "toolCall": {"name": "run_command", "args": {"CommandLine": command}},
        }

        with patch("sys.stdin", io.StringIO(json.dumps(payload))), patch("sys.stdout", new_callable=io.StringIO) as output:
            jev_gate.main()
            self.assertEqual(json.loads(output.getvalue())["decision"], "deny")

        payload["userMessage"] = "Proceed with removal"
        with patch("sys.stdin", io.StringIO(json.dumps(payload))), patch("sys.stdout", new_callable=io.StringIO) as output:
            jev_gate.main()
            result = json.loads(output.getvalue())

        self.assertEqual(result["decision"], "deny")
        self.assertIn("denied earlier", result["reason"])

    def test_main_fast_pass(self):
        payload = {
            "conversationId": "conversation-a",
            "toolCall": {"name": "run_command", "args": {"CommandLine": "git status"}},
        }

        with patch("sys.stdin", io.StringIO(json.dumps(payload))), patch("sys.stdout", new_callable=io.StringIO) as output:
            jev_gate.main()
            result = json.loads(output.getvalue())

        self.assertEqual(result["decision"], "allow")
        self.assertEqual(result["permissionOverrides"], ["command(git status)"])

    def test_main_invalid_payload_is_denied(self):
        with patch("sys.stdin", io.StringIO("not json")), patch("sys.stdout", new_callable=io.StringIO) as output:
            jev_gate.main()
            result = json.loads(output.getvalue())

        self.assertEqual(result["decision"], "deny")

    def test_main_missing_key_is_denied_and_recorded(self):
        payload = {
            "conversationId": "conversation-a",
            "toolCall": {"name": "run_command", "args": {"CommandLine": "python3 script.py"}},
        }

        with patch("jev_gate.get_api_key", return_value=""):
            with patch("sys.stdin", io.StringIO(json.dumps(payload))), patch("sys.stdout", new_callable=io.StringIO) as output:
                jev_gate.main()
                result = json.loads(output.getvalue())

        self.assertEqual(result["decision"], "deny")
        self.assertEqual(jev_gate.is_denied_command("python3 script.py", "conversation-a"), (True, None))


if __name__ == "__main__":
    unittest.main()
