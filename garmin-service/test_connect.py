#!/usr/bin/env python3
"""
Manual end-to-end test for /login, /login/mfa, and /sync — run this
YOURSELF in your own terminal. It prompts for your Garmin email/password
directly (hidden input via getpass), never as a command-line argument or
env var that could leak into shell history or `ps`. The password is
dropped from this process's memory immediately after the /login call.

Usage:
    python3 test_connect.py
Env vars (optional):
    GARMIN_SERVICE_URL   default http://127.0.0.1:8099
    INTERNAL_API_SECRET  if unset, you'll be prompted for it
"""
import getpass
import json
import os
import sys
import urllib.error
import urllib.request

BASE_URL = os.environ.get("GARMIN_SERVICE_URL", "http://127.0.0.1:8099")
SECRET = os.environ.get("INTERNAL_API_SECRET") or getpass.getpass(
    "INTERNAL_API_SECRET (same one the server was started with): "
)


def call(path: str, payload: dict) -> dict:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        f"{BASE_URL}{path}",
        data=data,
        method="POST",
        headers={"X-Internal-Secret": SECRET, "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        print(f"HTTP {e.code}: {e.read().decode()}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"Could not reach {BASE_URL} — is the server running? ({e})", file=sys.stderr)
        sys.exit(1)


def main():
    email = input("Garmin email: ").strip()
    password = getpass.getpass("Garmin password (hidden): ")

    print("Calling /login ...")
    result = call("/login", {"email": email, "password": password})
    password = None  # drop it from memory as soon as it's no longer needed

    if result["status"] == "mfa_required":
        print("MFA required — check your email/phone for the code Garmin just sent.")
        code = input("MFA code: ").strip()
        print("Calling /login/mfa ...")
        result = call("/login/mfa", {"session_id": result["session_id"], "code": code})

    if result["status"] != "connected":
        print("Unexpected result:", result)
        sys.exit(1)

    token_bundle = result["token_bundle"]
    print(f"\nConnected. Token bundle received ({len(token_bundle)} chars).")

    with open("test_token_bundle.json", "w") as f:
        f.write(token_bundle)
    print("Saved to test_token_bundle.json (gitignored) — don't paste its contents anywhere, including to me.")

    if input("\nTest /sync with this token now? [y/N] ").strip().lower() == "y":
        print("Calling /sync ...")
        sync_result = call("/sync", {"token_bundle": token_bundle, "days": 3})
        print(f"status: {sync_result['status']}")
        print(f"wellness records: {len(sync_result.get('wellness') or [])}")
        print(f"activities: {len(sync_result.get('activities') or [])}")


if __name__ == "__main__":
    main()
