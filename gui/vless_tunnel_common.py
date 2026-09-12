"""Shared backend helper for the GTK4 GUI and the GTK3 tray indicator.

Deliberately GTK-independent (only stdlib) so both processes can import it
regardless of which GTK major version they've loaded — see the tray's own
module docstring for why they're separate processes in the first place.
"""
import os
import subprocess

APP_BIN = os.environ.get("VLESS_APP_BIN", "vless-tunnel")


def run(args, input_text=None, timeout=30, escalate=True):
    """Run `sudo -n vless-tunnel <args>`, return (rc, stdout, stderr).

    Everyday commands work silently once `install` has written the NOPASSWD
    sudoers rule. Before that (first run, or if the rule is missing for any
    reason), `sudo -n` refuses to even start the command — the exact wording
    varies ("a password is required", "interactive authentication is
    required", ...), but sudo's own refusals are always prefixed "sudo:",
    unlike output from vless-tunnel itself. When `escalate` is true we treat
    any such refusal as "needs a graphical prompt" and retry once through
    `pkexec`.
    """
    cmd = ["sudo", "-n", APP_BIN, *args]
    try:
        p = subprocess.run(
            cmd, input=input_text, capture_output=True, text=True, timeout=timeout
        )
    except Exception as exc:  # noqa: BLE001
        return 1, "", str(exc)
    if escalate and p.returncode != 0 and (p.stderr or "").strip().startswith("sudo:"):
        try:
            p = subprocess.run(
                ["pkexec", APP_BIN, *args],
                input=input_text, capture_output=True, text=True, timeout=max(timeout, 180),
            )
        except Exception as exc:  # noqa: BLE001
            return 1, "", str(exc)
    return p.returncode, p.stdout, p.stderr
