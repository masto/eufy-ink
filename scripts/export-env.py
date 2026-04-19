#!/usr/bin/env python3
"""
Extract credentials from the eufyMake Studio profile cache and print them
as shell-export commands. Run this once on the machine that has the desktop
app installed, then copy the output to your container host.

Usage:
    python3 scripts/export-env.py                    # print to stdout
    python3 scripts/export-env.py --device-index 0   # pick a different device
    python3 scripts/export-env.py > .env              # save to .env file
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.parse
from pathlib import Path

PROFILE_CANDIDATES = [
    "~/Library/Application Support/eufyMake Studio Profile",  # macOS
    "~/AppData/Roaming/eufyMake Studio Profile",  # Windows
    "~/.config/eufyMake Studio Profile",  # Linux
    "~/Library/Application Support/AnkerMake Studio Profile",  # legacy
]


def find_profile() -> Path:
    override = os.environ.get("EUFY_PROFILE_DIR")
    roots = [override] + PROFILE_CANDIDATES if override else PROFILE_CANDIDATES
    for raw in roots:
        p = Path(os.path.expanduser(raw))
        if (p / "cache/offline/device_info/device_list.json").exists():
            return p
    raise SystemExit(
        "couldn't find the eufyMake Studio profile directory; sign in to "
        "the desktop app once, or set EUFY_PROFILE_DIR."
    )


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        description="Print eufy-ink credentials as shell-export commands"
    )
    p.add_argument(
        "--device-index",
        type=int,
        default=0,
        help="pick a device when more than one is registered (default: 0)",
    )
    p.add_argument(
        "--quiet",
        action="store_true",
        help="suppress the header comment",
    )
    args = p.parse_args(argv)

    profile = find_profile()
    dl = json.loads(
        (profile / "cache/offline/device_info/device_list.json").read_text()
    )
    li = json.loads((profile / "cache/offline/user_info/login_info.json").read_text())
    devices = dl.get("data") or []
    if args.device_index >= len(devices):
        raise SystemExit(
            f"--device-index {args.device_index} out of range "
            f"(have {len(devices)} devices)"
        )
    dev = devices[args.device_index]
    data = li.get("data") or {}

    user_id = data["user_id"]
    email = urllib.parse.unquote(data.get("email", ""))
    ab_code = data.get("ab_code") or "US"
    station_sn = dev["station_sn"]
    secret_key = dev["secret_key"]

    if not args.quiet:
        print(
            "# Run these commands or save to a .env file.\n"
            "# Copy this file to your container host.\n"
            "# Credentials from: " + str(profile.resolve()) + "\n#"
        )
        print(
            "# NOTE: Keep this file private — it contains your MQTT password and AES key.\n"
        )

    print(f"export EUFY_USER_ID={user_id}")
    print(f"export EUFY_EMAIL={email}")
    print(f"export EUFY_REGION={ab_code}")
    print(f"export EUFY_STATION_SN={station_sn}")
    print(f"export EUFY_SECRET_KEY={secret_key}")

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
