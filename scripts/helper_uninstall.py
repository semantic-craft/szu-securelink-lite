#!/usr/bin/env python3
"""Uninstall the privileged status helper and verify nothing remains.

Root bootstraps the job out, clears the immutable flag, removes both files and
verifies the absence with launchctl. Refuses when nothing is installed.
"""
import argparse
import datetime
import json
from pathlib import Path
import shlex
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import helper_install  # noqa: E402


def build_root_script() -> str:
    lines = [
        "set -eu",
        f"/bin/launchctl bootout system/{shlex.quote(helper_install.LABEL)} >/dev/null 2>&1 || true",
        f"if [ -f {shlex.quote(helper_install.HELPER_DEST)} ]; then "
        f"/usr/bin/chflags nouchg {shlex.quote(helper_install.HELPER_DEST)}; fi",
        f"/bin/rm -f {shlex.quote(helper_install.HELPER_DEST)}",
        f"/bin/rm -f {shlex.quote(helper_install.PLIST_DEST)}",
        f"if /bin/launchctl print system/{shlex.quote(helper_install.LABEL)} >/dev/null 2>&1; then exit 66; fi",
        f"if [ -e {shlex.quote(helper_install.HELPER_DEST)} ] || [ -e {shlex.quote(helper_install.PLIST_DEST)} ]; "
        f"then exit 67; fi",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    if not Path(helper_install.PLIST_DEST).exists() and not Path(helper_install.HELPER_DEST).exists():
        raise SystemExit("helper is not installed")
    script = build_root_script()
    run = subprocess.run([
        "osascript", "-e", "on run argv",
        "-e", "do shell script (item 1 of argv) with administrator privileges",
        "-e", "end run", script,
    ], capture_output=True, timeout=180)
    if run.returncode != 0:
        raise SystemExit("administrator authorization failed: " + run.stderr.decode()[-400:])
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    receipt = helper_install.write_receipt(f"uninstall-{stamp}.json", {
        "label": helper_install.LABEL,
        "uninstalledAt": stamp,
        "verifiedAbsent": True,
    })
    print(json.dumps({"uninstalled": True, "receipt": str(receipt)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
