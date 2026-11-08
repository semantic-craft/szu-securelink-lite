"""Execute the exact pinned overlay dispatch body with a socket-free harness."""
import hashlib
import pathlib
import runpy
import shlex
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / "out/openvpn3/source"
RELATIVE = pathlib.Path("openvpn/client/cliproto.hpp")


class ControlDispatchTests(unittest.TestCase):
    def test_unreviewed_control_header_rejected(self):
        prepare = runpy.run_path(str(ROOT / "scripts/build-openvpn3-eval"))["prepare_control_overlay"]
        with tempfile.TemporaryDirectory() as folder:
            source = pathlib.Path(folder) / "source"
            (source / RELATIVE).parent.mkdir(parents=True)
            (source / RELATIVE).write_text("unreviewed")
            with self.assertRaises(ValueError):
                prepare(source, pathlib.Path(folder) / "overlay")

    @unittest.skipUnless((SOURCE / RELATIVE).is_file(), "optional pinned dependency not fetched")
    def test_actual_dispatch_normalizes_and_stops_before_standard_reload(self):
        prepare = runpy.run_path(str(ROOT / "scripts/build-openvpn3-eval"))["prepare_control_overlay"]
        original = (SOURCE / RELATIVE).read_bytes()
        with tempfile.TemporaryDirectory(prefix="ctrl-dispatch-") as folder:
            folder = pathlib.Path(folder)
            receipt = prepare(SOURCE, folder / "overlay")
            modified = (folder / "overlay" / RELATIVE).read_text()
            self.assertEqual((SOURCE / RELATIVE).read_bytes(), original)
            self.assertEqual(receipt["baseSHA256"], hashlib.sha256(original).hexdigest())
            self.assertEqual(receipt, prepare(SOURCE, folder / "overlay"))
            begin = modified.index("    void control_recv(BufferPtr &&app_bp) override")
            end = modified.index("\n    /**", begin)
            body = modified[begin:end]
            self.assertLess(body.index("Unicode::is_valid_utf8"), body.index("normalize_control"))
            self.assertLess(body.index("normalize_control"), body.index("recv_push_reply"))
            translation = r'''
#define OPENVPN_LOG_NTNL(...) do {} while(false)
#define OPENVPN_LOG(...) do {} while(false)
#include <openvpn/client/szu_control_capture.hpp>
#include <cassert>
#include <memory>
#include <iostream>
using BufferPtr = std::shared_ptr<std::string>;
namespace Unicode = openvpn::Unicode;
namespace string { bool starts_with(const std::string &s, const std::string &p) { return s.compare(0,p.size(),p)==0; } }
struct ProtoContext { template<class T> static T read_control_string(const std::string &s) { return s; } };
struct ClientHalt { static bool match(const std::string &) { return false; } };
struct Transport { virtual ~Transport() = default; };
struct Reusable : SzuControlTransportConfig<Transport> {
    using SzuControlTransportConfig::SzuControlTransportConfig;
    void reconnect() { reset_control_connection(); }
};
struct Parent { virtual void control_recv(BufferPtr &&) = 0; virtual ~Parent() = default; };
struct Dispatch : Parent {
    std::shared_ptr<Transport> transport_factory;
    bool info = false;
    int replies = 0, updates = 0, auth = 0;
    std::string forwarded; // synthetic fixture only, never used in production
    void recv_push_reply(const std::string &m) { ++replies; forwarded = m; }
    void recv_push_update(const std::string &) { ++updates; }
    void recv_auth_failed(const std::string &) { ++auth; }
    void recv_halt_restart(const std::string &) {}
    void recv_info(const std::string &, bool) {}
    void recv_auth_pending(const std::string &) {}
    void recv_relay() {}
    void recv_custom_control_message(const std::string &) {}
''' + body + r'''
    void send(const std::string &s) { control_recv(std::make_shared<std::string>(s)); }
};
int main() {
    unsigned stopped = 0;
    Dispatch d;
    d.transport_factory = std::make_shared<SzuControlTransportConfig<Transport>>([&] { ++stopped; });
    d.send("PUSH_REPLY,ctrl domain:one.example sourceIp:192.0.2.1,push-continuation 2");
    assert(d.replies == 0 && stopped == 0);
    d.send("PUSH_REPLY,route 192.0.2.1,push-continuation 1");
    assert(d.replies == 1 && d.forwarded == "PUSH_REPLY,ctrl domain:one.example sourceIp:192.0.2.1,route 192.0.2.1");
    d.send("PUSH_REPLY,auth-token synthetic-secret");
    assert(d.replies == 2 && stopped == 0);
    d.send("PUSH_RELOAD_ALL,ctrl domain:two.example sourceIp:192.0.2.2");
    assert(stopped == 1 && d.replies == 2 && d.updates == 0);
    d.send("PUSH_REPLY,auth-token ignored-secret");
    assert(stopped == 1 && d.replies == 2);
    // Fresh factory starts fresh state; no global or scoped callback leakage.
    d.transport_factory = std::make_shared<SzuControlTransportConfig<Transport>>([&] { ++stopped; });
    d.send("AUTH_FAILED,synthetic");
    assert(d.auth == 1);
    d.send("PUSH_RELOAD_ALL,");
    assert(stopped == 2 && d.updates == 0);
    d.transport_factory = std::make_shared<SzuControlTransportConfig<Transport>>([&] { ++stopped; });
    std::string csv = "ctrl domain:compressed.example sourceIp:192.0.2.3";
    std::string raw(4, '\0'); raw[3] = static_cast<char>(csv.size()+5);
    std::string block(LZ4_compressBound(csv.size()), '\0');
    auto bytes = LZ4_compress_default(csv.data(), block.data(), csv.size(), block.size());
    raw.append(block.data(), bytes);
    d.send("PUSH_REPLY_LZ4," + openvpn::Base64().encode(raw));
    assert(d.replies == 3 && d.forwarded == "PUSH_REPLY," + csv);
    d.send("PUSH_UPDATE,route 192.0.2.2");
    assert(d.updates == 0 && stopped == 3);
    d.transport_factory = std::make_shared<SzuControlTransportConfig<Transport>>([&] { ++stopped; });
    d.send("PUSH_REPLY_LZ4,invalid-secret");
    assert(stopped == 4 && d.replies == 3);
    auto reused = std::make_shared<Reusable>([&] { ++stopped; });
    d.transport_factory = reused;
    d.send("PUSH_REPLY," + csv);
    reused->reconnect();
    d.send("PUSH_REPLY,route 192.0.2.8,push-continuation 2");
    assert(d.replies == 4); // fresh connection accumulates instead of auth refresh
    d.send("PUSH_REPLY," + csv + ",push-continuation 1");
    assert(d.replies == 5 && stopped == 4);
    std::cout << "control dispatch: passed\n";
}
'''
            cpp = folder / "dispatch.cpp"
            cpp.write_text(translation)
            flags = shlex.split(subprocess.run(["pkg-config", "--cflags", "--libs", "liblz4"],
                                              check=True, capture_output=True, text=True).stdout)
            binary = folder / "dispatch"
            compiled = subprocess.run([shutil.which("clang++") or "c++", "-std=c++17", "-Wall", "-Wextra", "-Werror",
                "-DUSE_ASIO", "-DASIO_STANDALONE", "-I", str(folder / "overlay"),
                "-isystem", str(SOURCE), "-isystem", str(ROOT / "out/openvpn3/asio/asio/include"),
                str(cpp), "-o", str(binary), *flags], capture_output=True, text=True, timeout=30)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            ran = subprocess.run([str(binary)], capture_output=True, text=True, timeout=5)
            self.assertEqual(ran.returncode, 0, ran.stderr)
            self.assertEqual(ran.stdout, "control dispatch: passed\n")
            self.assertEqual(ran.stderr, "")


if __name__ == "__main__":
    unittest.main()
