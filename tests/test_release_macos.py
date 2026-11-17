#!/usr/bin/env python3
"""Behavioral tests for scripts/release-macos, scripts/build-app, and notary policy compliance."""
from __future__ import annotations

import os
from pathlib import Path
import plistlib
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parents[1]
RELEASE_SCRIPT = REPO_ROOT / "scripts" / "release-macos"
BUILD_APP_SCRIPT = REPO_ROOT / "scripts" / "build-app"


def make_executable(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def build_minimal_app(
    parent: Path,
    *,
    name: str = "荔连.app",
    version: str = "0.2.3",
    bundle_id: str = "local.szu.securelink.preview",
    executable: str = "szu-securelink",
    with_nested_helpers: bool = True,
) -> Path:
    app = parent / name
    macos_dir = app / "Contents" / "MacOS"
    resources_dir = app / "Contents" / "Resources"
    macos_dir.mkdir(parents=True, exist_ok=True)
    resources_dir.mkdir(parents=True, exist_ok=True)
    make_executable(macos_dir / executable, "#!/bin/sh\nexit 0\n")
    if with_nested_helpers:
        make_executable(macos_dir / "szu-securelink-diagnostic", "#!/bin/sh\nexit 0\n")
        make_executable(macos_dir / "executor-engine", "#!/bin/sh\nexit 0\n")

    info = {
        "CFBundleExecutable": executable,
        "CFBundleIdentifier": bundle_id,
        "CFBundleName": "荔连",
        "CFBundleDisplayName": "荔连",
        "CFBundlePackageType": "APPL",
        "CFBundleShortVersionString": version,
        "CFBundleVersion": "4",
    }
    with (app / "Contents" / "Info.plist").open("wb") as handle:
        plistlib.dump(info, handle)
    return app


def create_stub_toolchain(root: Path) -> tuple[Path, Path]:
    stub_bin = root / "bin"
    stub_bin.mkdir(parents=True, exist_ok=True)
    log_file = root / "calls.log"
    log_file.write_text("", encoding="utf-8")

    make_executable(
        stub_bin / "codesign",
        """#!/bin/sh
set -eu
printf 'codesign %s\\n' "$*" >> "$STUB_LOG"
case " $* " in
  *" --verify "*)
    exit "${STUB_CODESIGN_VERIFY_EXIT:-0}"
    ;;
  *" -dvvv "*)
    if [ "${STUB_CODESIGN_EXIT:-0}" != "0" ]; then
      echo "code object is not signed at all" >&2
      exit "${STUB_CODESIGN_EXIT}"
    fi
    target=""
    for arg in "$@"; do
      target="$arg"
    done
    case "$target" in
      */executor-engine) echo "Identifier=local.szu.securelink.executor-engine" ;;
      */szu-securelink-diagnostic) echo "Identifier=local.szu.securelink.diagnostic" ;;
      *) echo "Identifier=${STUB_CODESIGN_IDENTIFIER:-local.szu.securelink.preview}" ;;
    esac
    if [ "${STUB_CODESIGN_ADHOC:-0}" = "1" ]; then
      echo "CodeDirectory v=20100 size=187 flags=0x2(adhoc) hashes=1+2 location=embedded"
      echo "Signature=adhoc"
      exit 0
    fi
    if [ "${STUB_CODESIGN_NO_RUNTIME:-0}" = "1" ]; then
      echo "CodeDirectory v=20500 size=187 flags=0x0(none) hashes=1+2 location=embedded"
    else
      echo "CodeDirectory v=20500 size=187 flags=0x10000(runtime) hashes=1+2 location=embedded"
    fi
    echo "Authority=${STUB_CODESIGN_AUTHORITY:-Developer ID Application: Fixture Signer (TEAM000001)}"
    if [ "${STUB_CODESIGN_TIMESTAMP_NONE:-0}" = "1" ]; then
      echo "Timestamp=none"
    elif [ "${STUB_CODESIGN_NO_TS:-0}" = "1" ]; then
      echo "Signed Time=Nov 17, 2026 at 8:00:00 AM"
    else
      echo "Timestamp=Nov 17, 2026 at 8:00:00 AM"
    fi
    exit 0
    ;;
esac
exit 0
""",
    )

    make_executable(
        stub_bin / "xcrun",
        """#!/bin/sh
set -eu
printf 'xcrun %s\\n' "$*" >> "$STUB_LOG"
case "${1:-}:${2:-}" in
  notarytool:submit)
    exit "${STUB_NOTARY_EXIT:-0}"
    ;;
  stapler:staple)
    exit "${STUB_STAPLE_EXIT:-0}"
    ;;
  stapler:validate)
    exit "${STUB_VALIDATE_EXIT:-0}"
    ;;
esac
exit 1
""",
    )

    make_executable(
        stub_bin / "spctl",
        """#!/bin/sh
set -eu
printf 'spctl %s\\n' "$*" >> "$STUB_LOG"
printf '%s\\n' "${STUB_SPCTL_OUT:-accepted
source=Notarized Developer ID}" >&2
exit "${STUB_SPCTL_EXIT:-0}"
""",
    )

    make_executable(
        stub_bin / "lsregister",
        """#!/bin/sh
set -eu
printf 'lsregister %s\\n' "$*" >> "$STUB_LOG"
exit 0
""",
    )

    make_executable(
        stub_bin / "security",
        """#!/bin/sh
set -eu
printf 'security %s\\n' "$*" >> "$STUB_LOG"
if [ "${STUB_SECURITY_MODE:-none}" = "dev_id" ]; then
  echo '  1) 1111111111111111111111111111111111111111 "Developer ID Application: Fixture Signer (TEAM000001)"'
else
  echo '     0 valid identities found'
fi
""",
    )

    return stub_bin, log_file


def make_env(stub_bin: Path, log_file: Path, home_dir: Path, extra: dict[str, str] | None = None) -> dict[str, str]:
    tmp_dir = stub_bin.parent / "tmp"
    home_dir.mkdir(parents=True, exist_ok=True)
    tmp_dir.mkdir(parents=True, exist_ok=True)
    env = {
        "PATH": f"{stub_bin}:/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": str(home_dir),
        "TMPDIR": str(tmp_dir),
        "STUB_LOG": str(log_file),
        "SZU_LSREGISTER": str(stub_bin / "lsregister"),
    }
    if extra:
        env.update(extra)
    return env


class ReleaseMacOSTests(unittest.TestCase):
    def test_fails_cleanly_on_real_adhoc_and_unsigned_bundles(self) -> None:
        if sys.platform != "darwin" or shutil.which("/usr/bin/codesign") is None:
            self.skipTest("requires macOS /usr/bin/codesign")

        with tempfile.TemporaryDirectory(prefix="szu-adhoc-") as tmp:
            root = Path(tmp).resolve()
            app = build_minimal_app(root, with_nested_helpers=False)
            stub_bin, log_file = create_stub_toolchain(root)
            # Remove stub codesign so real /usr/bin/codesign inspects the real bundle.
            (stub_bin / "codesign").unlink()

            env = make_env(stub_bin, log_file, root / "home", {"NOTARY_PROFILE": "fixture-profile"})

            unsigned = subprocess.run(
                [str(RELEASE_SCRIPT), "--app", str(app)],
                cwd=REPO_ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(unsigned.returncode, 0)
            unsigned_calls = log_file.read_text(encoding="utf-8").splitlines()
            self.assertFalse(any(c.startswith(("xcrun ", "macos-notary ", "spctl ")) for c in unsigned_calls), unsigned_calls)

            subprocess.run(["/usr/bin/codesign", "--force", "--sign", "-", str(app)], check=True)
            adhoc = subprocess.run(
                [str(RELEASE_SCRIPT), "--app", str(app)],
                cwd=REPO_ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(adhoc.returncode, 0)
            self.assertRegex(adhoc.stderr.lower(), r"ad-?hoc|developer id")
            calls = log_file.read_text(encoding="utf-8").splitlines()
            self.assertFalse(any(c.startswith(("xcrun ", "macos-notary ", "spctl ")) for c in calls), calls)
            self.assertEqual(list(root.glob("*.zip")), [])
            self.assertFalse((root / "SHA256SUMS.txt").exists())

    def test_fails_cleanly_when_runtime_or_timestamp_or_developer_id_missing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="szu-preflight-") as tmp:
            root = Path(tmp).resolve()
            app = build_minimal_app(root)
            stub_bin, log_file = create_stub_toolchain(root)
            home = root / "home"

            cases = [
                {"STUB_CODESIGN_NO_RUNTIME": "1"},
                {"STUB_CODESIGN_NO_TS": "1"},
                {"STUB_CODESIGN_TIMESTAMP_NONE": "1"},
                {"STUB_CODESIGN_AUTHORITY": "Apple Development: Test User (TEAM000001)"},
            ]
            for extra in cases:
                log_file.write_text("", encoding="utf-8")
                env = make_env(stub_bin, log_file, home, {"NOTARY_PROFILE": "fixture-profile", **extra})
                proc = subprocess.run(
                    [str(RELEASE_SCRIPT), "--app", str(app)],
                    cwd=REPO_ROOT,
                    env=env,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertNotEqual(proc.returncode, 0, extra)
                calls = log_file.read_text(encoding="utf-8").splitlines()
                self.assertFalse(any(c.startswith(("xcrun ", "macos-notary ")) for c in calls), (extra, calls))

    def test_resolves_notary_profile_precedence_and_fails_loudly_when_empty(self) -> None:
        with tempfile.TemporaryDirectory(prefix="szu-profile-") as tmp:
            root = Path(tmp).resolve()
            app = build_minimal_app(root)
            stub_bin, log_file = create_stub_toolchain(root)
            home = root / "home"

            # Empty: neither NOTARY_PROFILE nor macos-notary-profile exists.
            missing = subprocess.run(
                [str(RELEASE_SCRIPT), "--app", str(app), "--out-dir", str(root / "dist0")],
                cwd=REPO_ROOT,
                env=make_env(stub_bin, log_file, home),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(missing.returncode, 0)
            self.assertIn("NOTARY_PROFILE", missing.stderr)

            # Fallback to $HOME/.local/bin/macos-notary-profile when not on PATH.
            local_profile_bin = home / ".local" / "bin" / "macos-notary-profile"
            make_executable(local_profile_bin, "#!/bin/sh\necho home-local-profile\n")
            p_home = subprocess.run(
                [str(RELEASE_SCRIPT), "--app", str(app), "--out-dir", str(root / "dist1")],
                cwd=REPO_ROOT,
                env=make_env(stub_bin, log_file, home),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(p_home.returncode, 0, p_home.stdout + p_home.stderr)
            calls_1 = log_file.read_text(encoding="utf-8").splitlines()
            self.assertTrue(
                any("notarytool submit " in c and "--keychain-profile home-local-profile" in c for c in calls_1),
                calls_1,
            )

            # PATH macos-notary-profile overrides $HOME/.local/bin/macos-notary-profile.
            log_file.write_text("", encoding="utf-8")
            make_executable(stub_bin / "macos-notary-profile", "#!/bin/sh\necho path-helper-profile\n")
            p_path = subprocess.run(
                [str(RELEASE_SCRIPT), "--app", str(app), "--out-dir", str(root / "dist2")],
                cwd=REPO_ROOT,
                env=make_env(stub_bin, log_file, home),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(p_path.returncode, 0, p_path.stdout + p_path.stderr)
            calls_2 = log_file.read_text(encoding="utf-8").splitlines()
            self.assertTrue(
                any("notarytool submit " in c and "--keychain-profile path-helper-profile" in c for c in calls_2),
                calls_2,
            )

            # NOTARY_PROFILE overrides macos-notary-profile.
            log_file.write_text("", encoding="utf-8")
            p_env = subprocess.run(
                [str(RELEASE_SCRIPT), "--app", str(app), "--out-dir", str(root / "dist3")],
                cwd=REPO_ROOT,
                env=make_env(stub_bin, log_file, home, {"NOTARY_PROFILE": "env-override-profile"}),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(p_env.returncode, 0, p_env.stdout + p_env.stderr)
            calls_3 = log_file.read_text(encoding="utf-8").splitlines()
            self.assertTrue(
                any("notarytool submit " in c and "--keychain-profile env-override-profile" in c for c in calls_3),
                calls_3,
            )

    def test_direct_notarytool_staple_spctl_zip_checksums_and_ls_cleanup(self) -> None:
        with tempfile.TemporaryDirectory(prefix="szu-direct-") as tmp:
            root = Path(tmp).resolve()
            app = build_minimal_app(root)
            out_dir = root / "dist"
            stub_bin, log_file = create_stub_toolchain(root)
            make_executable(stub_bin / "macos-notary-profile", "#!/bin/sh\necho direct-profile\n")

            proc = subprocess.run(
                [str(RELEASE_SCRIPT), "--app", str(app), "--out-dir", str(out_dir)],
                cwd=REPO_ROOT,
                env=make_env(stub_bin, log_file, root / "home"),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

            calls = log_file.read_text(encoding="utf-8").splitlines()
            submit_idx = next(
                (i for i, c in enumerate(calls) if c.startswith("xcrun notarytool submit ") and "--keychain-profile direct-profile" in c),
                -1,
            )
            staple_idx = next((i for i, c in enumerate(calls) if c == f"xcrun stapler staple {app}"), -1)
            validate_idx = next((i for i, c in enumerate(calls) if c == f"xcrun stapler validate {app}"), -1)
            spctl_idx = next(
                (i for i, c in enumerate(calls) if c == f"spctl --assess --type execute --verbose=4 {app}"),
                -1,
            )
            self.assertGreaterEqual(submit_idx, 0, calls)
            self.assertGreater(staple_idx, submit_idx, calls)
            self.assertGreater(validate_idx, staple_idx, calls)
            self.assertGreater(spctl_idx, validate_idx, calls)
            self.assertIn(f"lsregister -u {app}", calls)

            zips = list(out_dir.glob("SZU-SecureLink-v0.2.3-macOS-*.zip"))
            self.assertEqual(len(zips), 1, zips)
            sums = out_dir / "SHA256SUMS.txt"
            self.assertTrue(sums.is_file())
            verify_sum = subprocess.run(
                ["shasum", "-a", "256", "-c", "SHA256SUMS.txt"],
                cwd=out_dir,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(verify_sum.returncode, 0, verify_sum.stdout + verify_sum.stderr)

    def test_spctl_rejects_unnotarized_output_and_wrapper_submits_with_profile(self) -> None:
        with tempfile.TemporaryDirectory(prefix="szu-wrapper-") as tmp:
            root = Path(tmp).resolve()
            app = build_minimal_app(root)
            stub_bin, log_file = create_stub_toolchain(root)
            make_executable(stub_bin / "macos-notary-profile", "#!/bin/sh\necho wrapper-profile\n")
            make_executable(
                stub_bin / "macos-notary",
                '#!/bin/sh\nset -eu\nprintf \'macos-notary %s\\n\' "$*" >> "$STUB_LOG"\n',
            )

            ok = subprocess.run(
                [str(RELEASE_SCRIPT), "--app", str(app), "--out-dir", str(root / "dist-ok")],
                cwd=REPO_ROOT,
                env=make_env(stub_bin, log_file, root / "home"),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
            calls = log_file.read_text(encoding="utf-8").splitlines()
            self.assertIn(f"macos-notary submit {app} --profile wrapper-profile", calls)
            self.assertIn(f"spctl --assess --type execute --verbose=4 {app}", calls)

            bad_spctl = subprocess.run(
                [str(RELEASE_SCRIPT), "--app", str(app), "--out-dir", str(root / "dist-bad")],
                cwd=REPO_ROOT,
                env=make_env(
                    stub_bin,
                    log_file,
                    root / "home",
                    {"STUB_SPCTL_EXIT": "0", "STUB_SPCTL_OUT": "accepted\nsource=Developer ID"},
                ),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(bad_spctl.returncode, 0)
            self.assertIn("Notarized Developer ID", bad_spctl.stderr)
            self.assertEqual(list((root / "dist-bad").glob("*.zip")), [])

    def test_install_flag_installs_atomically_and_build_app_notarize_requires_dev_id(self) -> None:
        with tempfile.TemporaryDirectory(prefix="szu-install-") as tmp:
            root = Path(tmp).resolve()
            app = build_minimal_app(root)
            install_dir = root / "Applications"
            stub_bin, log_file = create_stub_toolchain(root)
            make_executable(stub_bin / "macos-notary-profile", "#!/bin/sh\necho install-profile\n")

            proc = subprocess.run(
                [str(RELEASE_SCRIPT), "--app", str(app), "--out-dir", str(root / "dist"), "--install"],
                cwd=REPO_ROOT,
                env=make_env(stub_bin, log_file, root / "home", {"SZU_INSTALL_DIR": str(install_dir)}),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            installed = install_dir / "荔连.app"
            self.assertTrue((installed / "Contents" / "MacOS" / "szu-securelink").is_file())
            calls = log_file.read_text(encoding="utf-8").splitlines()
            self.assertIn(f"lsregister -u {app}", calls)
            self.assertIn(f"lsregister -f {installed}", calls)

            no_id = subprocess.run(
                [str(BUILD_APP_SCRIPT), "--notarize", str(root / "Out.app")],
                cwd=REPO_ROOT,
                env=make_env(stub_bin, log_file, root / "home", {"STUB_SECURITY_MODE": "none"}),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(no_id.returncode, 0)
            self.assertIn("Developer ID Application", no_id.stderr)

    def test_notary_policy_gate_passes_on_repo(self) -> None:
        explicit = os.environ.get("NOTARY_POLICY_CHECK", "").strip()
        candidate = Path(explicit) if explicit else REPO_ROOT.parent / "agent-home/tools/notary-check/check_notary_policy.py"
        if not candidate.is_file():
            self.skipTest(f"Notary policy checker not present at {candidate}")
        proc = subprocess.run(
            [sys.executable, str(candidate), "--visibility", "public", str(REPO_ROOT)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("0 finding(s)", proc.stdout)


if __name__ == "__main__":
    unittest.main()
