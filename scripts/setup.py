#!/usr/bin/env python3
"""Configure the TypeSafe API credential used by agy-jevgate."""

import getpass
import platform
import subprocess
import sys

SERVICE_NAME = "agy-jevgate"
ACCOUNT_NAME = "api_key"


def save_to_macos_keychain(api_key: str) -> bool:
    command = [
        "security",
        "add-generic-password",
        "-s", SERVICE_NAME,
        "-a", ACCOUNT_NAME,
        "-w", api_key,
        "-U",
    ]
    try:
        subprocess.run(command, check=True, capture_output=True, text=True)
    except (OSError, subprocess.CalledProcessError) as error:
        detail = getattr(error, "stderr", "") or str(error)
        print(f"Failed to store key in Keychain: {detail.strip()}", file=sys.stderr)
        return False
    return True


def check_macos_keychain() -> bool:
    command = [
        "security",
        "find-generic-password",
        "-s", SERVICE_NAME,
        "-a", ACCOUNT_NAME,
        "-w",
    ]
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
    except (OSError, subprocess.CalledProcessError):
        return False
    return bool(result.stdout.strip())


def delete_macos_keychain() -> bool:
    command = [
        "security",
        "delete-generic-password",
        "-s", SERVICE_NAME,
        "-a", ACCOUNT_NAME,
    ]
    try:
        subprocess.run(command, check=True, capture_output=True, text=True)
    except (OSError, subprocess.CalledProcessError) as error:
        detail = getattr(error, "stderr", "") or str(error)
        print(f"Failed to delete key from Keychain: {detail.strip()}", file=sys.stderr)
        return False
    return True


def main() -> int:
    if "--check" in sys.argv:
        if check_macos_keychain():
            print(f"API key is present in Keychain (service: '{SERVICE_NAME}').")
            return 0
        print(f"No API key found in Keychain (service: '{SERVICE_NAME}').")
        return 1

    if "--delete" in sys.argv:
        if delete_macos_keychain():
            print(f"Removed API key from Keychain (service: '{SERVICE_NAME}').")
            return 0
        return 1

    if platform.system() != "Darwin":
        print("Interactive setup currently supports macOS (Darwin) only.", file=sys.stderr)
        print("On other platforms, configure apiKeyCommand in ~/.config/agy-jevgate/config.json.", file=sys.stderr)
        return 1

    print("=== agy-jevgate setup ===")
    print("Securely stores your TypeSafe API key in the macOS Keychain.")
    print("No environment variables or plaintext files are created.\n")

    try:
        api_key = getpass.getpass("Enter TypeSafe API Key (input hidden): ").strip()
    except (KeyboardInterrupt, EOFError):
        print("\nSetup cancelled.")
        return 1

    if not api_key:
        print("Error: API key cannot be empty.", file=sys.stderr)
        return 1

    if not save_to_macos_keychain(api_key):
        return 1
    print(f"\nStored TypeSafe API key in macOS Keychain under service '{SERVICE_NAME}'.")
    print("Antigravity CLI (agy) will retrieve the key during hook execution.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
