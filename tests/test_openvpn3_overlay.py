import hashlib
from pathlib import Path
import runpy
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
prepare = runpy.run_path(str(ROOT / "scripts/build-openvpn3-eval"))["prepare_transport_overlay"]
RELATIVE = Path("openvpn/transport/client/tcpcli.hpp")


class TransportOverlayTests(unittest.TestCase):
    def test_unreviewed_source_is_rejected_without_overlay(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            (source / RELATIVE).parent.mkdir(parents=True)
            (source / RELATIVE).write_text("unreviewed transport")
            with self.assertRaises(ValueError):
                prepare(source, root / "overlay")
            self.assertFalse((root / "overlay").exists())

    @unittest.skipUnless((ROOT / "out/openvpn3/source" / RELATIVE).is_file(), "optional pinned dependency not fetched")
    def test_overlay_preserves_source_and_connects_only_existing_mutation_hook(self):
        source = ROOT / "out/openvpn3/source"
        original = (source / RELATIVE).read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            overlay = Path(directory)
            receipt = prepare(source, overlay)
            patched = (overlay / RELATIVE).read_text()
            self.assertEqual((source / RELATIVE).read_bytes(), original)
            self.assertEqual(receipt["baseSHA256"], hashlib.sha256(original).hexdigest())
            self.assertEqual(receipt["overlaySHA256"], hashlib.sha256(patched.encode()).hexdigest())
            self.assertEqual(patched.count("std::function<TransportMutateStream::Ptr()> make_mutator;"), 1)
            self.assertEqual(patched.count("stream->set_mutate(config->make_mutator());"), 1)
            self.assertLess(patched.index("stream->set_mutate"), patched.index("impl->start();"))
            self.assertIn("SPDX-License-Identifier:", patched)
            self.assertEqual(prepare(source, overlay), receipt)


class DomainOverlayTests(unittest.TestCase):
    def test_unknown_header_is_rejected(self):
        prepare_domain = runpy.run_path(str(ROOT / "scripts/build-openvpn3-eval"))["prepare_domain_overlay"]
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            relative = Path("openvpn/tun/client/tunprop.hpp")
            (source / relative).parent.mkdir(parents=True)
            (source / relative).write_text("unreviewed")
            with self.assertRaises(ValueError):
                prepare_domain(source, Path(directory) / "overlay")
            self.assertFalse((Path(directory) / "overlay").exists())

    @unittest.skipUnless((ROOT / "out/openvpn3/source/openvpn/tun/client/tunprop.hpp").is_file(), "optional source")
    def test_hook_is_single_pinned_early_helper_only_and_preserves_source(self):
        prepare_domain = runpy.run_path(str(ROOT / "scripts/build-openvpn3-eval"))["prepare_domain_overlay"]
        source = ROOT / "out/openvpn3/source"
        relative = Path("openvpn/tun/client/tunprop.hpp")
        original = (source / relative).read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            overlay = Path(directory)
            receipt = prepare_domain(source, overlay)
            patched = (overlay / relative).read_text()
            self.assertEqual((source / relative).read_bytes(), original)
            self.assertEqual(patched.count("capture->capture_domain_options(opt)"), 1)
            self.assertLess(patched.index("capture->capture_domain_options(opt)"), patched.index("IP::Addr::VersionMask ip_ver_flags"))
            self.assertEqual(receipt["overlaySHA256"], hashlib.sha256(patched.encode()).hexdigest())
            self.assertEqual(prepare_domain(source, overlay), receipt)
        cmake = (ROOT / "native/openvpn3-eval/CMakeLists.txt").read_text()
        self.assertIn('target_include_directories(szu-openvpn3-handshake BEFORE PRIVATE "${OPENVPN3_OVERLAY}")', cmake)
        self.assertNotIn('target_include_directories(szu-openvpn3-eval BEFORE PRIVATE "${OPENVPN3_OVERLAY}")', cmake)
