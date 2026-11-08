#!/usr/bin/env python3
"""Build, stage and install the privileged read-only status helper.

The root script copies digest-verified files into root-owned locations and
bootstraps a launchd job; it never executes a user-writable file directly.
`--dry-run` prints the exact root command without touching the system.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shlex
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "out" / "helper-install"
BUILD = ROOT / "out" / "helper-build"
LABEL = "local.szu.securelink.helper"
HELPER_DEST = "/Library/PrivilegedHelperTools/" + LABEL
PLIST_DEST = "/Library/LaunchDaemons/" + LABEL + ".plist"
SOCKET_PATH = "/var/run/" + LABEL
LISTENER_NAME = "Listeners"
CHANGED_FLAG = "uchg"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def build_daemon(binary_dest: Path) -> None:
    binary_dest.parent.mkdir(parents=True, exist_ok=True)
    build = subprocess.run([
        "xcrun", "clang++", "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror",
        "-framework", "Foundation",
        str(ROOT / "native/network-helper/status_daemon_main.mm"),
        "-o", str(binary_dest),
    ], capture_output=True, timeout=120)
    if build.returncode != 0:
        raise SystemExit("daemon build failed: " + build.stderr.decode()[-800:])


def run_offline_daemon_test() -> None:
    with tempfile.TemporaryDirectory(prefix="status-daemon-test-") as temporary:
        binary = Path(temporary) / "status-daemon-test"
        build = subprocess.run([
            "xcrun", "clang++", "-std=c++17", "-Wall", "-Wextra", "-Werror",
            "-framework", "Foundation",
            str(ROOT / "native/network-helper/status_daemon_test.mm"), "-o", str(binary),
        ], capture_output=True, timeout=60)
        if build.returncode != 0:
            raise SystemExit("offline test build failed: " + build.stderr.decode()[-800:])
        run = subprocess.run([str(binary)], capture_output=True, timeout=10)
        if run.returncode != 0 or run.stdout != b"":
            raise SystemExit("offline daemon logic test failed")


def generate_plist(allowed_uid: int) -> bytes:
    if not 0 <= allowed_uid <= 1000000:
        raise ValueError("implausible uid")
    job = {
        "Label": LABEL,
        "ProgramArguments": [HELPER_DEST, "--allowed-uid", str(allowed_uid)],
        "Sockets": {LISTENER_NAME: {
            "SockPathName": SOCKET_PATH,
            "SockPathMode": 0o666,
            "SockType": "STREAM",
        }},
        "RunAtLoad": False,
        "KeepAlive": False,
    }
    return plistlib.dumps(job, fmt=plistlib.FMT_XML)


def build_root_script(binary_src: Path, plist_src: Path, binary_sha: str, plist_sha: str) -> str:
    # Every line uses absolute paths; digests are re-verified as root right
    # before the copy so the staged copy, not the user-owned source, is what
    # launchd will later execute.
    lines = [
        "set -eu",
        "umask 077",
        f"/bin/mkdir -p {shlex.quote(str(Path(HELPER_DEST).parent))}",
        f"actual=$(/usr/bin/shasum -a 256 {shlex.quote(str(binary_src))})",
        f'[ "${{actual%% *}}" = {binary_sha} ] || exit 65',
        f"actual=$(/usr/bin/shasum -a 256 {shlex.quote(str(plist_src))})",
        f'[ "${{actual%% *}}" = {plist_sha} ] || exit 65',
        f"if [ -f {shlex.quote(HELPER_DEST)} ]; then /usr/bin/chflags nouchg {shlex.quote(HELPER_DEST)}; fi",
        f"/bin/cp -f {shlex.quote(str(binary_src))} {shlex.quote(HELPER_DEST)}",
        f"/bin/cp -f {shlex.quote(str(plist_src))} {shlex.quote(PLIST_DEST)}",
        f"/usr/sbin/chown root:wheel {shlex.quote(HELPER_DEST)} {shlex.quote(PLIST_DEST)}",
        f"/bin/chmod 0755 {shlex.quote(HELPER_DEST)}",
        f"/bin/chmod 0644 {shlex.quote(PLIST_DEST)}",
        f"actual=$(/usr/bin/shasum -a 256 {shlex.quote(HELPER_DEST)})",
        f'[ "${{actual%% *}}" = {binary_sha} ] || exit 65',
        f"actual=$(/usr/bin/shasum -a 256 {shlex.quote(PLIST_DEST)})",
        f'[ "${{actual%% *}}" = {plist_sha} ] || exit 65',
        f"/usr/bin/chflags {CHANGED_FLAG} {shlex.quote(HELPER_DEST)}",
        f"/bin/launchctl bootout system/{shlex.quote(LABEL)} >/dev/null 2>&1 || true",
        f"/bin/launchctl bootstrap system {shlex.quote(PLIST_DEST)}",
        f"/bin/launchctl print system/{shlex.quote(LABEL)} >/dev/null",
    ]
    return "\n".join(lines) + "\n"


def write_receipt(name: str, payload: dict) -> Path:
    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / name
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return path


def prepare() -> dict:
    run_offline_daemon_test()
    binary = BUILD / LABEL
    build_daemon(binary)
    binary_sha = sha256_file(binary)
    uid = os.getuid()
    plist_bytes = generate_plist(uid)
    plist_path = BUILD / (LABEL + ".plist")
    plist_path.write_bytes(plist_bytes)
    plist_sha = sha256_file(plist_path)
    script = build_root_script(binary, plist_path, binary_sha, plist_sha)
    return {
        "binary": str(binary),
        "plist": str(plist_path),
        "binarySha256": binary_sha,
        "plistSha256": plist_sha,
        "allowedUid": uid,
        "rootScript": script,
    }


def osascript_admin(script: str) -> str:
    # The script travels as an argv string, so no AppleScript escaping is
    # involved and any shell content passes through verbatim.
    run = subprocess.run([
        "osascript", "-e", "on run argv",
        "-e", "do shell script (item 1 of argv) with administrator privileges",
        "-e", "end run", script,
    ], capture_output=True, timeout=180)
    if run.returncode != 0:
        raise SystemExit("administrator authorization failed: " + run.stderr.decode()[-400:])
    return run.stdout.decode()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true",
                        help="prepare and print the root command without installing")
    parser.add_argument("--replace", action="store_true",
                        help="replace an existing installation in one step")
    args = parser.parse_args()

    staged = prepare()
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    if args.dry_run:
        print(json.dumps({k: v for k, v in staged.items() if k != "rootScript"},
                         indent=2, sort_keys=True))
        print("--- root script ---")
        print(staged["rootScript"], end="")
        return 0

    for target in (HELPER_DEST, PLIST_DEST):
        if Path(target).exists() and not args.replace:
            raise SystemExit(f"{target} already exists; run scripts/uninstall-helper first")

    osascript_admin(staged["rootScript"])
    receipt = write_receipt(f"install-{stamp}.json", {
        "label": LABEL,
        "helperPath": HELPER_DEST,
        "plistPath": PLIST_DEST,
        "socketPath": SOCKET_PATH,
        "binarySha256": staged["binarySha256"],
        "plistSha256": staged["plistSha256"],
        "allowedUid": staged["allowedUid"],
        "installedAt": stamp,
    })
    print(json.dumps({
        "installed": True,
        "label": LABEL,
        "receipt": str(receipt),
        "binarySha256": staged["binarySha256"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
