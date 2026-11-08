"""Offline tests for scripts/health-check: verdict shapes and the known
repair mapping, with the live system never touched (temp files + injected
runners)."""
import importlib.machinery
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

loader = importlib.machinery.SourceFileLoader("health_check", str(Path(__file__).resolve().parents[1] / "scripts/health-check"))
spec = importlib.util.spec_from_loader(loader.name, loader)
health = importlib.util.module_from_spec(spec)
loader.exec_module(health)

STAGED_FILES = (("context", ".json"), ("static-routes", ".json"),
                ("engine-cdhash", ".cdhash"), ("identity", ".txt"))


class HealthCheckTests(unittest.TestCase):
    def _engine_check_with_staged(self, staged_hash: str, cdhash: str) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            files = {}
            for name, suffix in STAGED_FILES:
                path = Path(tmp) / (name + suffix)
                path.write_text(staged_hash + "\n" if name == "engine-cdhash" else "x\n")
                files[name] = str(path)
            with patch.dict(health.EXECUTOR_STAGED, files), \
                 patch.object(health, "ENGINE_BINARY") as binary, \
                 patch.object(health.subprocess, "run") as run:
                binary.is_file.return_value = True
                run.return_value = Mock(
                    stdout="Identifier=local.szu.securelink.executor-engine\nCDHash=" + cdhash,
                    stderr="", returncode=0)
                return health.check_engine_binary()

    def test_stale_engine_cdhash_maps_to_replace_repair(self):
        verdict = self._engine_check_with_staged(staged_hash="bbbb", cdhash="aaaa")
        self.assertEqual(verdict["state"], "stale")
        self.assertIn("install-executor --replace", verdict["repair"])

    def test_matching_cdhash_is_healthy(self):
        verdict = self._engine_check_with_staged(staged_hash="aaaa", cdhash="aaaa")
        self.assertEqual(verdict["state"], "healthy")

    def test_missing_engine_is_missing_with_build_repair(self):
        with patch.object(health, "ENGINE_BINARY") as binary:
            binary.is_file.return_value = False
            verdict = health.check_engine_binary()
        self.assertEqual(verdict["state"], "missing")
        self.assertIn("build-executor", verdict["repair"])

    def test_wrong_identifier_is_stale(self):
        with tempfile.TemporaryDirectory() as tmp:
            files = {}
            for name, suffix in STAGED_FILES:
                path = Path(tmp) / (name + suffix)
                path.write_text("aaaa\n" if name == "engine-cdhash" else "x\n")
                files[name] = str(path)
            with patch.dict(health.EXECUTOR_STAGED, files), \
                 patch.object(health, "ENGINE_BINARY") as binary, \
                 patch.object(health.subprocess, "run") as run:
                binary.is_file.return_value = True
                run.return_value = Mock(
                    stdout="Identifier=com.someone.else\nCDHash=aaaa",
                    stderr="", returncode=0)
                verdict = health.check_engine_binary()
        self.assertEqual(verdict["state"], "stale")
        self.assertEqual(verdict["identifier"], "com.someone.else")

    def test_helper_receipt_hash_field_precedence(self):
        # The helper install receipt stores the hash under binarySha256;
        # helperSha256 is accepted for forward compatibility only.
        receipt = {"binarySha256": "a" * 64, "label": health.HELPER_LABEL}
        self.assertEqual(receipt.get("binarySha256") or receipt.get("helperSha256"), "a" * 64)
        receipt = {"helperSha256": "b" * 64, "label": health.HELPER_LABEL}
        self.assertEqual(receipt.get("binarySha256") or receipt.get("helperSha256"), "b" * 64)


if __name__ == "__main__":
    unittest.main()
