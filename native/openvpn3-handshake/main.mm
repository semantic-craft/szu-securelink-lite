#import <Foundation/Foundation.h>
#include "probe.hpp"
#include "probe_input.hpp"
#include <openvpn/tun/client/tunprop.hpp>
#include <array>
#include <cstdio>
#include <cstring>
#include <memory>
#include <sys/resource.h>
#include <unistd.h>

namespace {
int receipt(const char *reason, int code, bool connectCalled = false, const HandshakeProbe *probe = nullptr) {
    std::string planJSON = "null";
    if (probe && probe->capturePlan && probe->plan.requested()) {
        planJSON = probe->plan.json();
        if (planJSON.size() > 48 * 1024) { planJSON = "null"; reason = "plan-limit"; code = 3; }
    }
    std::printf("{\"planCaptureRequested\":%s,\"planComplete\":%s,\"plan\":%s,", probe && probe->capturePlan ? "true" : "false",
                probe && probe->capturePlan && probe->plan.isComplete() && planJSON != "null" ? "true" : "false", planJSON.c_str());
    const char *confusion = probe && probe->vendorConfusion ? "true" : "false";
    std::printf("\"vendorConfusion\":%s,\"clientCertificateSuppressed\":%s,", confusion, confusion);
    std::printf("\"activeShapingNotExercised\":%s,\"gmsslRenegotiationNotExercised\":%s,",
                probe && probe->activeShapingNotExercised ? "true" : "false",
                probe && probe->gmsslRenegotiationNotExercised ? "true" : "false");
    std::printf("\"mode\":\"bounded-handshake-probe\",\"reason\":\"%s\",\"connectCalled\":%s,\"socketObserved\":%s,\"tunnelSetupRequested\":%s,\"tunnelStarted\":false,\"connected\":false,\"routesChanged\":false,\"dnsChanged\":false,\"deadlineReached\":%s,\"unexpectedConnected\":%s,\"eventsDropped\":%s,\"events\":[",
                reason, connectCalled ? "true" : "false", probe && probe->socketObserved ? "true" : "false",
                probe && probe->tunnelSetupRequested ? "true" : "false", probe && probe->deadlineReached ? "true" : "false",
                probe && probe->unexpectedConnected ? "true" : "false", probe && probe->eventsDropped ? "true" : "false");
    if (probe) for (std::size_t index = 0; index < probe->events.size(); ++index)
        std::printf("%s\"%s\"", index ? "," : "", probe->events[index]);
    std::puts("]}");
    return code;
}
int planSelfTest(bool omitMTU = false) {
    // These use the exact production callback overrides; no connect()/socket/OS setup.
    HandshakeProbe probe(false, false, false, true);
    if (!probe.tun_builder_new() || !probe.capture_domain_options(openvpn::OptionList{}) || !probe.tun_builder_set_layer(3)
        || !probe.tun_builder_set_remote_address("192.0.2.1", false)
        || !probe.tun_builder_add_address("10.8.0.2", 24, "10.8.0.1", false, false)
        || !probe.tun_builder_add_address("2001:db8:1::2", 64, "", true, false)
        || !probe.tun_builder_set_route_metric_default(-1)
        || !probe.tun_builder_add_route("10.20.0.0", 16, -1, false)
        || !probe.tun_builder_exclude_route("192.0.2.1", 32, -1, false)
        || !probe.tun_builder_reroute_gw(false, false, 256)
        || !probe.tun_builder_set_mtu(1400)
        || !probe.tun_builder_set_allow_family(AF_INET, true)
        || !probe.tun_builder_set_allow_family(AF_INET6, false)
        || !probe.tun_builder_set_allow_local_dns(true)
        || !probe.tun_builder_set_session_name("SECRET-SESSION-TOKEN")) return receipt("self-test-failed", 3);
    openvpn::DnsOptions dns;
    dns.from_dhcp_options = true;
    dns.servers[0].addresses.emplace_back("192.0.2.53");
    dns.servers[0].domains.emplace_back("example.edu");
    dns.search_domains.emplace_back("dept.example.edu");
    if (!probe.tun_builder_set_dns_options(dns) || probe.tun_builder_establish() != -1 || !probe.plan.isComplete()
        || probe.plan.json().find("SECRET") != std::string::npos || probe.plan.json().size() > 48*1024) return receipt("self-test-failed", 3);
    auto rejects = [](auto callback) {
        MemoryTunPlan plan;
        plan.tun_builder_new();
        const bool accepted = callback(plan);
        return !accepted && !plan.isComplete() && plan.json().find("SECRET") == std::string::npos;
    };
    if (!rejects([](auto &p) { return p.tun_builder_set_remote_address("SECRET", false); })
        || !rejects([](auto &p) { return p.tun_builder_add_address("192.0.2.1", 33, "", false, false); })
        || !rejects([](auto &p) { return p.tun_builder_add_address("2001:db8::1", 64, "", true, true); })
        || !rejects([](auto &p) { return p.tun_builder_add_address("192.0.2.1", 24, "2001:db8::1", false, false); })
        || !rejects([](auto &p) { return p.tun_builder_add_route("SECRET", 32, -1, false); })
        || !rejects([](auto &p) { return p.tun_builder_add_route("192.0.2.0", 24, -2, false); })
        || !rejects([](auto &p) { return p.tun_builder_reroute_gw(true, false, 1u<<31); })
        || !rejects([](auto &p) { return p.tun_builder_set_mtu(65536); })
        || !rejects([](auto &p) { return p.tun_builder_set_layer(2); })
        || !rejects([](auto &p) { return p.tun_builder_set_proxy_http("SECRET", 80); })
        || !rejects([](auto &p) { return p.tun_builder_add_wins_server("SECRET"); })
        || !rejects([](auto &p) { return p.tun_builder_set_allow_family(-1, false); })
        || !rejects([](auto &p) { p.tun_builder_set_mtu(1400); return p.tun_builder_set_mtu(1500); })
        || !rejects([](auto &p) { return p.tun_builder_new(); })
        || !rejects([](auto &p) {
            for (int i=0; i<64; ++i) if (!p.tun_builder_add_route("192.0.2.0", 24, -1, false)) return true;
            return p.tun_builder_add_route("192.0.2.0", 24, -1, false);
        }) || !rejects([](auto &p) {
            openvpn::DnsOptions d; d.servers[0].addresses.emplace_back("192.0.2.53");
            d.servers[0].transport = openvpn::DnsServer::Transport::HTTPS;
            return p.tun_builder_set_dns_options(d);
        }) || !rejects([](auto &p) {
            openvpn::DnsOptions d; d.search_domains.emplace_back("SECRET\"INJECTION");
            return p.tun_builder_set_dns_options(d);
        }) || !rejects([](auto &p) {
            openvpn::DnsOptions d; for (int i=0; i<33; ++i) d.search_domains.emplace_back("example.edu");
            return p.tun_builder_set_dns_options(d);
        })) return receipt("self-test-failed", 3);
    for (const auto &value : {std::string("*"), std::string("bad*example.edu"), std::string("SECRET\"INJECTION"), std::string("!example.edu"), std::string(254, 'a')}) {
        if (!rejects([&](auto &p) {
            openvpn::OptionList o; o.add_item(openvpn::Option{"domain", value}); o.update_map();
            return p.capture_domain_options(o);
        })) return receipt("self-test-failed", 3);
    }
    if (!rejects([](auto &p) {
        openvpn::OptionList o; o.add_item(openvpn::Option{"domain", "example.edu", "SECRET"}); o.update_map();
        return p.capture_domain_options(o);
    }) || !rejects([](auto &p) {
        openvpn::OptionList o; for (int i=0; i<65; ++i) o.add_item(openvpn::Option{"domain", "example.edu"}); o.update_map();
        return p.capture_domain_options(o);
    })) return receipt("self-test-failed", 3);
    if (!rejects([](auto &p) {
        openvpn::OptionList o;
        o.add_item(openvpn::Option{"ctrl", "unknown SECRET-POLICY"}); o.update_map();
        return p.capture_domain_options(o);
    })) return receipt("self-test-failed", 3);
    MemoryTunPlan incomplete;
    if (incomplete.tun_builder_set_mtu(1400) || incomplete.isComplete()) return receipt("self-test-failed", 3);
    MemoryTunPlan missing;
    missing.tun_builder_new(); missing.tun_builder_establish();
    if (missing.isComplete() || missing.json().find("incomplete-plan") == std::string::npos) return receipt("self-test-failed", 3);
    // A completed capture cannot subsequently mutate or be reused as a second builder.
    MemoryTunPlan sealed;
    sealed.tun_builder_new(); sealed.capture_domain_options(openvpn::OptionList{}); sealed.tun_builder_set_layer(3); sealed.tun_builder_set_mtu(1400);
    sealed.tun_builder_set_remote_address("192.0.2.1", false);
    sealed.tun_builder_add_address("10.8.0.2", 24, "", false, false); sealed.tun_builder_establish();
    if (sealed.tun_builder_add_route("192.0.2.0",24,-1,false) || sealed.isComplete()) return receipt("self-test-failed", 3);
    // Exercise upstream configure_builder as well, so callback ordering and defaults are real.
    HandshakeProbe upstream(false, false, false, true);
    openvpn::OptionList options;
    options.add_item(openvpn::Option{"topology", "subnet"});
    options.add_item(openvpn::Option{"route-gateway", "10.8.0.1"});
    options.add_item(openvpn::Option{"ifconfig", "10.8.0.2", "255.255.255.0"});
    options.add_item(openvpn::Option{"route", "10.20.0.0", "255.255.0.0"});
    options.add_item(openvpn::Option{"dhcp-option", "DNS", "192.0.2.53"});
    options.add_item(openvpn::Option{"dhcp-option", "DOMAIN", "example.edu"});
    options.add_item(openvpn::Option{"domain", "finance.example.edu"});
    options.add_item(openvpn::Option{"domain", "*.example.edu"});
    options.add_item(openvpn::Option{"domain", ".another.example.edu"});
    options.update_map();
    openvpn::TunProp::Config config;
    if (!omitMTU) config.mtu = 1400;
    options.add_item(openvpn::Option{"ctrl", "domain:portal.example.edu", "sourceIp:192.0.2.5;192.0.2.6"});
    options.update_map();
    config.mtu_max = 65535; config.session_name = "SECRET-UPSTREAM-SESSION";
    openvpn::TunProp::State state;
    if (!upstream.tun_builder_new()) return receipt("self-test-failed", 3);
    openvpn::TunProp::configure_builder(&upstream, &state, nullptr, openvpn::IP::Addr("192.0.2.1"), config, options, nullptr, true);
    if (upstream.tun_builder_establish() != -1 || !upstream.plan.isComplete()
        || upstream.plan.json().find("SECRET") != std::string::npos
        || upstream.plan.json().find("10.20.0.0") == std::string::npos
        || upstream.plan.json().find("example.edu") == std::string::npos
        || upstream.plan.json().find("*.example.edu") == std::string::npos) return receipt("self-test-failed", 3);
    if (omitMTU && upstream.plan.json().find("\"mtu\":null") == std::string::npos) return receipt("self-test-failed", 3);
    return receipt("plan-self-test-passed", 0, false, omitMTU ? &upstream : &probe);
}
int selfTest() {
    // Exercise the real upstream buffer adapter, not only the vector codec.
    const std::array<unsigned char, 5> standard{0, 3, 0x40, 1, 2};
    ConfusionStream stream;
    openvpn::BufferAllocated outgoing(standard.data(), standard.size(), 0);
    stream.pre_send(outgoing);
    const std::array<unsigned char, 7> wire{0, 5, 0, 0, 0x40, 1, 2};
    if (outgoing.size() != wire.size() || std::memcmp(outgoing.c_data(), wire.data(), wire.size()) != 0)
        return receipt("self-test-failed", 3);
    for (std::size_t count = 0; count < wire.size(); ++count) {
        openvpn::BufferAllocated fragment(wire.data() + count, 1, 0);
        stream.post_recv(fragment);
        if (count + 1 < wire.size()) {
            if (!fragment.empty()) return receipt("self-test-failed", 3);
        } else if (fragment.size() != standard.size() || std::memcmp(fragment.c_data(), standard.data(), standard.size()) != 0)
            return receipt("self-test-failed", 3);
    }
    openvpn::BufferAllocated combined(2 * wire.size(), 0);
    combined.write(wire.data(), wire.size()); combined.write(wire.data(), wire.size());
    stream.post_recv(combined);
    if (combined.size() != 2 * standard.size()
        || std::memcmp(combined.c_data(), standard.data(), standard.size()) != 0
        || std::memcmp(combined.c_data() + standard.size(), standard.data(), standard.size()) != 0)
        return receipt("self-test-failed", 3);
    HandshakeProbe plain, transformed(true);
    openvpn::ExternalTransport::Config transport;
    transport.protocol = openvpn::Protocol(openvpn::Protocol::TCP);
    auto *plainWrapper = dynamic_cast<SzuProbeTransportFactory *>(plain.new_transport_factory(transport));
    auto *transformedWrapper = dynamic_cast<SzuProbeTransportFactory *>(transformed.new_transport_factory(transport));
    auto *plainFactory = plainWrapper ? dynamic_cast<const openvpn::TCPTransport::ClientConfig *>(plainWrapper->underlying()) : nullptr;
    auto *transformedFactory = transformedWrapper ? dynamic_cast<const openvpn::TCPTransport::ClientConfig *>(transformedWrapper->underlying()) : nullptr;
    if (!plainFactory || plainFactory->make_mutator || !transformedFactory || !transformedFactory->make_mutator)
        return receipt("self-test-failed", 3);
    auto firstStream = transformedFactory->make_mutator(), secondStream = transformedFactory->make_mutator();
    if (firstStream.get() == secondStream.get()) return receipt("self-test-failed", 3);
    openvpn::BufferAllocated partial(wire.data(), 1, 0), fresh(wire.data(), wire.size(), 0);
    firstStream->post_recv(partial); secondStream->post_recv(fresh);
    if (!partial.empty() || fresh.size() != standard.size() || std::memcmp(fresh.c_data(), standard.data(), standard.size()) != 0)
        return receipt("self-test-failed", 3);
    transport.protocol = openvpn::Protocol(openvpn::Protocol::UDP);
    bool rejected = false;
    try { transformed.new_transport_factory(transport); } catch (...) { rejected = true; }
    if (!rejected) return receipt("self-test-failed", 3);
    HandshakeProbe probe;
    if (probe.tun_builder_new() || probe.tun_builder_establish() != -1 || !probe.tunnelSetupRequested) return receipt("self-test-failed", 3);
    openvpn::ClientAPI::Event unknown;
    unknown.name = "SECRET-UNKNOWN"; unknown.info = "SECRET-INFO";
    probe.event(unknown);
    openvpn::ClientAPI::Event known;
    known.name = "AUTH_FAILED"; known.info = "SECRET-TOKEN"; known.error = true;
    for (int index = 0; index < 40; ++index) probe.event(known);
    if (probe.events.size() != 32 || !probe.eventsDropped) return receipt("self-test-failed", 3);
    // Hook mode (merged data engine): capture runs first, establish delegates
    // to the hook only with a completed capture, and CONNECTED is expected.
    HandshakeProbe hooked(false, false, false, true);
    int hookFd = -1;
    hooked.establishHook = [&hookFd] { hookFd = 4242; return hookFd; };
    if (!hooked.tun_builder_new() || !hooked.capture_domain_options(openvpn::OptionList{})
        || !hooked.tun_builder_set_layer(3)
        || !hooked.tun_builder_set_remote_address("192.0.2.1", false)
        || !hooked.tun_builder_add_address("10.8.0.2", 24, "10.8.0.1", false, false)
        || !hooked.tun_builder_set_mtu(1400)) return receipt("self-test-failed", 3);
    if (hooked.tun_builder_establish() != 4242 || hookFd != 4242 || !hooked.plan.isComplete())
        return receipt("self-test-failed", 3);
    HandshakeProbe incomplete(false, false, false, true);
    bool hookRan = false;
    incomplete.establishHook = [&hookRan] { hookRan = true; return 4243; };
    if (!incomplete.tun_builder_new() || !incomplete.tun_builder_set_layer(3)
        || incomplete.tun_builder_establish() != -1 || hookRan || incomplete.plan.isComplete())
        return receipt("self-test-failed", 3);
    HandshakeProbe bare;
    bool bareRan = false;
    bare.establishHook = [&bareRan] { bareRan = true; return 4244; };
    if (bare.tun_builder_new() != true || bare.tun_builder_establish() != -1 || bareRan)
        return receipt("self-test-failed", 3);
    HandshakeProbe dataProbe;
    dataProbe.dataFd = 4245;
    openvpn::ClientAPI::Event connected;
    connected.name = "CONNECTED";
    dataProbe.event(connected);
    if (!dataProbe.connectedInDataMode.load() || dataProbe.unexpectedConnected) return receipt("self-test-failed", 3);
    std::atomic<bool> expired{false};
    {
        StopDeadline deadline(std::chrono::steady_clock::now() + std::chrono::milliseconds(2), [&] { expired = true; });
        for (int count = 0; count < 100 && !expired; ++count) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    if (!expired) return receipt("self-test-failed", 3);
    probe.deadlineReached = expired.load();
    return receipt("self-test-passed", 0, false, &probe);
}
}
int main(int argc, char **argv) {
    const pid_t owner = getppid();
    const pid_t group = owner > 1 ? getpgid(owner) : -1;
    if (group <= 0 || setpgid(0, group) != 0) return receipt("invalid-input", 3);
    alarm(300); // data-mode sessions hold longer; stdin covers the rest
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(297);
    const rlimit noCore = {0, 0}; setrlimit(RLIMIT_CORE, &noCore);
    @autoreleasepool {
        bool connectCalled = false;
        std::unique_ptr<HandshakeProbe> activeProbe;
        try {
            if (argc != 2 && argc != 3) return receipt("invalid-input", 3);
            if (argc == 2 && std::strcmp(argv[1], "--self-test") == 0) return selfTest();
            if (argc == 2 && std::strcmp(argv[1], "--plan-self-test") == 0) return planSelfTest();
            if (argc == 2 && std::strcmp(argv[1], "--plan-default-mtu-self-test") == 0) return planSelfTest(true);
            const bool capturePlan = argc == 3 && std::strcmp(argv[2], "--capture-plan") == 0;
            if (argc == 3 && !capturePlan) return receipt("invalid-input", 3);
            // Data mode: --data-mode --tun-fd N --hold-ms M — the utun fd was
            // received from the executor transaction; the TUN boundary opens
            // and the session runs the real data channel for hold-ms.
            int dataFd = -1;
            long long holdMs = 0;
            if (argc >= 2 && std::strcmp(argv[1], "--data-mode") == 0) {
                if (argc != 7) return receipt("invalid-input", 3);
                if (std::strcmp(argv[2], "--tun-fd") != 0 || std::strcmp(argv[4], "--hold-ms") != 0)
                    return receipt("invalid-input", 3);
                dataFd = std::atoi(argv[3]);
                holdMs = std::atoll(argv[5]);
                if (dataFd <= 0 || holdMs <= 0 || holdMs > 300000) return receipt("invalid-input", 3);
            }
            const bool allowHandshake = std::strcmp(argv[1], "--allow-handshake") == 0;
            if (!allowHandshake && std::strcmp(argv[1], "--validate-input") != 0 &&
                std::strcmp(argv[1], "--data-mode") != 0) return receipt("invalid-input", 3);
            std::string input;
            std::array<char, 8192> buffer{};
            for (;;) {
                const auto count = ::read(STDIN_FILENO, buffer.data(), buffer.size());
                if (count < 0) return receipt("invalid-input", 3);
                if (!count) break;
                if (input.size() + static_cast<std::size_t>(count) > 2 * 1024 * 1024) return receipt("invalid-input", 3);
                input.append(buffer.data(), static_cast<std::size_t>(count));
            }
            probe_input::Parsed parsed;
            if (!probe_input::parse(input, parsed)) return receipt("invalid-input", 3);
            std::vector<openvpn::ClientAPI::KeyValue> peerInfo;
            for (auto &entry : parsed.peerInfo) peerInfo.emplace_back(entry.first, std::move(entry.second));
            activeProbe = std::make_unique<HandshakeProbe>(parsed.vendorConfusion, parsed.activeShapingNotExercised,
                                                           parsed.gmsslRenegotiationNotExercised, capturePlan);
            auto &probe = *activeProbe;
            if (dataFd >= 0) probe.dataFd = ::fcntl(dataFd, F_DUPFD_CLOEXEC, 3);
            openvpn::ClientAPI::Config config;
            config.peerInfo = std::move(peerInfo);
            config.content = std::move(parsed.profile);
            config.connTimeout = 25;
            config.retryOnAuthFailed = false;
            config.tunPersist = false;
            config.googleDnsFallback = false;
            // Official positive confusion disables only local client certificate
            // presentation; server CA verification remains upstream's default.
            config.disableClientCert = parsed.vendorConfusion;
            // Keep upstream TLS certificate verification and authentication defaults unchanged.
            const auto evaluation = probe.eval_config(config);
            if (evaluation.error) return receipt("profile-rejected", 2, false, &probe);
            if ((parsed.vendorConfusion || parsed.activeShapingNotExercised || parsed.gmsslRenegotiationNotExercised)
                && !openvpn::Protocol::parse(evaluation.remoteProto, openvpn::Protocol::CLIENT_SUFFIX).is_tcp())
                return receipt("profile-rejected", 2, false, &probe);
            openvpn::ClientAPI::ProvideCreds credentials;
            credentials.username = std::move(parsed.username); credentials.password = std::move(parsed.password);
            if (probe.provide_creds(credentials).error) return receipt("credentials-rejected", 2, false, &probe);
            if (!allowHandshake) return receipt("input-validated", 0, false, &probe);
            if (std::chrono::steady_clock::now() >= deadline) {
                probe.deadlineReached = true;
                return receipt("deadline", 2, false, &probe);
            }
            {
                const auto hold = probe.dataSession() ? std::chrono::milliseconds(holdMs) : std::chrono::milliseconds(0);
                StopDeadline timer(deadline, [&] { probe.deadlineReached = true; probe.stop(); });
                StopDeadline holdTimer(std::chrono::steady_clock::now() + hold,
                                       [&] { probe.stop(); }); // data hold ends the session
                connectCalled = true;
                const auto status = probe.connect();
                (void)status; // status/message may include secrets; never render them
            }
            const char *reason = probe.controlPolicyRejected ? "control-policy-rejected" :
                                 probe.connectedInDataMode ? "data-session-ended" :
                                 probe.unexpectedConnected ? "unexpected-connected" :
                                 probe.tunnelSetupRequested ? "tunnel-boundary" :
                                 probe.deadlineReached ? "deadline" : "connection-ended";
            return receipt(reason, 2, true, &probe);
        } catch (...) { return receipt("internal-error", 3, connectCalled, activeProbe.get()); }
    }
}
