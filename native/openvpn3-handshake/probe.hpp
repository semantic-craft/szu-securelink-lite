#pragma once
#include <client/ovpncli.hpp>
#include "confusion_transport.hpp"
#include "plan.hpp"
#include <openvpn/tun/client/szu_domain_capture.hpp>
#include <openvpn/client/szu_control_capture.hpp>
#include <openvpn/transport/client/extern/config.hpp>
#include <openvpn/transport/client/tcpcli.hpp>
#include <openvpn/transport/client/udpcli.hpp>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

// Owns and joins its timer; no detached background work survives the probe.
class StopDeadline {
    std::mutex mutex;
    std::condition_variable condition;
    bool finished = false;
    std::thread timer;
public:
    StopDeadline(std::chrono::steady_clock::time_point deadline, std::function<void()> stop)
        : timer([this, deadline, stop = std::move(stop)] {
            std::unique_lock<std::mutex> lock(mutex);
            if (!condition.wait_until(lock, deadline, [this] { return finished; })) {
                lock.unlock();
                stop();
            }
        }) {}
    ~StopDeadline() {
        { std::lock_guard<std::mutex> lock(mutex); finished = true; }
        condition.notify_all();
        timer.join();
    }
};

// Composition preserves the pinned TCP/UDP factories' private constructors.
class SzuProbeTransportFactory final : public SzuControlTransportConfig<openvpn::TransportClientFactory> {
    openvpn::TransportClientFactory::Ptr delegate;
public:
    SzuProbeTransportFactory(openvpn::TransportClientFactory::Ptr factory, std::function<void()> reject,
        std::function<void(const std::vector<securelink::ctrl::PushRouteIntent> &)> pushUpdate = nullptr)
        : SzuControlTransportConfig(std::move(reject), std::move(pushUpdate)), delegate(std::move(factory)) {}
    openvpn::TransportClient::Ptr new_transport_client_obj(openvpn_io::io_context &io,
            openvpn::TransportClientParent *parent) override {
        reset_control_connection();
        return delegate->new_transport_client_obj(io, parent);
    }
    // Read-only inspection for the offline transport-configuration self-test.
    const openvpn::TransportClientFactory *underlying() const { return delegate.get(); }
    bool is_relay() override { return delegate->is_relay(); }
    void process_push(const openvpn::OptionList &options) override { delegate->process_push(options); }
};

class HandshakeProbe final : public openvpn::ClientAPI::OpenVPNClient, public SzuDomainOptionCapture {
    openvpn::TransportClientFactory::Ptr transportConfig;
public:
    // Unit 4: set by the data engine only. When absent, a route push still
    // fails the session closed exactly as in the handshake probe.
    std::function<void(const std::vector<securelink::ctrl::PushRouteIntent> &)> pushUpdateHandler;
public:
    explicit HandshakeProbe(bool confusion = false, bool shaping = false, bool gmsslTimer = false, bool capture = false)
        : capturePlan(capture), vendorConfusion(confusion), activeShapingNotExercised(shaping), gmsslRenegotiationNotExercised(gmsslTimer) {}
    const bool capturePlan;
    MemoryTunPlan plan;
    bool controlPolicyRejected = false;
    void rejectControlPolicy() { controlPolicyRejected = true; plan.reject("unsupported-control-policy"); stop(); }
    bool captureResult(bool result) { if (!result) stop(); return result; }
    const bool vendorConfusion;
    const bool activeShapingNotExercised;
    const bool gmsslRenegotiationNotExercised;
    openvpn::TransportClientFactory *new_transport_factory(const openvpn::ExternalTransport::Config &conf) override {
        if (conf.protocol.is_tcp()) {
            auto config = openvpn::TCPTransport::ClientConfig::new_obj();
            config->remote_list = conf.remote_list;
            config->frame = conf.frame;
            config->stats = conf.stats;
            config->socket_protect = conf.socket_protect;
            if (vendorConfusion) config->make_mutator = [] {
                return openvpn::TransportMutateStream::Ptr(new ConfusionStream());
            };
            transportConfig.reset(new SzuProbeTransportFactory(config, [this] { rejectControlPolicy(); },
                pushUpdateHandler));
        } else if (conf.protocol.is_udp() && !vendorConfusion) {
            auto config = openvpn::UDPTransport::ClientConfig::new_obj();
            config->remote_list = conf.remote_list;
            config->frame = conf.frame;
            config->stats = conf.stats;
            config->socket_protect = conf.socket_protect;
            config->server_addr_float = conf.server_addr_float;
            transportConfig.reset(new SzuProbeTransportFactory(config, [this] { rejectControlPolicy(); },
                pushUpdateHandler));
        } else { throw std::runtime_error("unsupported probe transport"); }
        return transportConfig.get();
    }
    bool tunnelSetupRequested = false;
    bool unexpectedConnected = false;
    bool socketObserved = false;
    bool eventsDropped = false;
    std::vector<const char *> events;
    std::atomic<bool> deadlineReached{false};
    bool pause_on_connection_timeout() override { return false; }
    void log(const openvpn::ClientAPI::LogInfo &) override {}
    void acc_event(const openvpn::ClientAPI::AppCustomControlMessageEvent &) override {}
    void external_pki_cert_request(openvpn::ClientAPI::ExternalPKICertRequest &request) override { request.error = true; }
    void external_pki_sign_request(openvpn::ClientAPI::ExternalPKISignRequest &request) override { request.error = true; }
    bool socket_protect(openvpn_io::detail::socket_type, std::string, bool) override {
        socketObserved = true;
        return true; // no socket options, routes or interface changes
    }
    // Data mode: the TUN boundary opens and the session runs the real data
    // channel. dataFd holds an executor-delivered utun fd (CLI --data-mode);
    // establishHook instead runs the executor transaction inside
    // tun_builder_establish (merged data engine) and returns its fd. With a
    // hook, capture semantics run first so the plan is complete before the
    // transaction; an incomplete capture fails closed without one.
    int dataFd = -1;
    std::function<int()> establishHook;
    std::atomic<bool> connectedInDataMode{false};
    bool dataSession() const { return dataFd >= 0 || static_cast<bool>(establishHook); }

    bool capture_domain_options(const openvpn::OptionList &options) override {
        return capturePlan ? captureResult(plan.capture_domain_options(options)) : true;
    }
    bool tun_builder_new() override {
        tunnelSetupRequested = true;
        if (capturePlan) return captureResult(plan.tun_builder_new());
        if (dataSession()) return true; // data mode: boundary opens, session continues
        stop();
        return false; // default barrier remains before all setters
    }
    int tun_builder_establish() override {
        tunnelSetupRequested = true;
        if (capturePlan) plan.tun_builder_establish();
        if (establishHook) {
            if (!plan.isComplete()) { stop(); return -1; } // incomplete capture fails closed
            return establishHook();
        }
        if (dataFd >= 0) return dataFd; // data mode: executor-delivered utun fd
        stop();
        return -1; // defense in depth; never creates an interface or returns an FD
    }
    bool tun_builder_set_layer(int value) override { return capturePlan ? captureResult(plan.tun_builder_set_layer(value)) : dataSession() ? true : captureResult(false); }
    bool tun_builder_set_remote_address(const std::string &address, bool ipv6) override { return capturePlan ? captureResult(plan.tun_builder_set_remote_address(address, ipv6)) : dataSession() ? true : captureResult(false); }
    bool tun_builder_add_address(const std::string &address, int prefix, const std::string &gateway, bool ipv6, bool net30) override { return capturePlan ? captureResult(plan.tun_builder_add_address(address, prefix, gateway, ipv6, net30)) : dataSession() ? true : captureResult(false); }
    bool tun_builder_set_route_metric_default(int metric) override { return capturePlan ? captureResult(plan.tun_builder_set_route_metric_default(metric)) : dataSession() ? true : captureResult(false); }
    bool tun_builder_add_route(const std::string &address, int prefix, int metric, bool ipv6) override { return capturePlan ? captureResult(plan.tun_builder_add_route(address, prefix, metric, ipv6)) : dataSession() ? true : captureResult(false); }
    bool tun_builder_exclude_route(const std::string &address, int prefix, int metric, bool ipv6) override { return capturePlan ? captureResult(plan.tun_builder_exclude_route(address, prefix, metric, ipv6)) : dataSession() ? true : captureResult(false); }
    bool tun_builder_reroute_gw(bool ipv4, bool ipv6, unsigned flags) override { return capturePlan ? captureResult(plan.tun_builder_reroute_gw(ipv4, ipv6, flags)) : dataSession() ? true : captureResult(false); }
    bool tun_builder_set_dns_options(const openvpn::DnsOptions &dns) override { return capturePlan ? captureResult(plan.tun_builder_set_dns_options(dns)) : dataSession() ? true : captureResult(false); }
    bool tun_builder_set_mtu(int value) override { return capturePlan ? captureResult(plan.tun_builder_set_mtu(value)) : dataSession() ? true : captureResult(false); }
    bool tun_builder_set_session_name(const std::string &name) override { return capturePlan ? captureResult(plan.tun_builder_set_session_name(name)) : dataSession() ? true : captureResult(false); }
    bool tun_builder_set_allow_family(int af, bool allow) override { return capturePlan ? captureResult(plan.tun_builder_set_allow_family(af, allow)) : dataSession() ? true : captureResult(false); }
    bool tun_builder_set_allow_local_dns(bool allow) override { return capturePlan ? captureResult(plan.tun_builder_set_allow_local_dns(allow)) : dataSession() ? true : captureResult(false); }
    bool tun_builder_add_proxy_bypass(const std::string &host) override { return capturePlan ? captureResult(plan.tun_builder_add_proxy_bypass(host)) : dataSession() ? true : captureResult(false); }
    bool tun_builder_set_proxy_auto_config_url(const std::string &url) override { return capturePlan ? captureResult(plan.tun_builder_set_proxy_auto_config_url(url)) : dataSession() ? true : captureResult(false); }
    bool tun_builder_set_proxy_http(const std::string &host, int port) override { return capturePlan ? captureResult(plan.tun_builder_set_proxy_http(host, port)) : dataSession() ? true : captureResult(false); }
    bool tun_builder_set_proxy_https(const std::string &host, int port) override { return capturePlan ? captureResult(plan.tun_builder_set_proxy_https(host, port)) : dataSession() ? true : captureResult(false); }
    bool tun_builder_add_wins_server(const std::string &address) override { return capturePlan ? captureResult(plan.tun_builder_add_wins_server(address)) : dataSession() ? true : captureResult(false); }
    std::vector<std::string> tun_builder_get_local_networks(bool ipv6) override { if (dataSession()) return {}; plan.tun_builder_get_local_networks(ipv6); stop(); return {}; }
    void tun_builder_establish_lite() override { if (dataSession()) return; plan.tun_builder_establish_lite(); stop(); }
    bool tun_builder_persist() override { return dataSession(); }
    void event(const openvpn::ClientAPI::Event &event) override {
        // Only literal names from this table may leave the process; no event.info.
        static constexpr std::array<const char *, 21> allowed = {
            "RESOLVE", "WAIT", "CONNECTING", "GET_CONFIG", "AUTH_PENDING", "AUTH_FAILED",
            "CERT_VERIFY_FAIL", "TLS_VERSION_MIN", "TLS_ALERT_UNKNOWN_CA", "TLS_ALERT_HANDSHAKE_FAILURE",
            "TLS_ALERT_CERTIFICATE_EXPIRED", "TLS_ALERT_CERTIFICATE_REVOKED", "DYNAMIC_CHALLENGE",
            "TRANSPORT_ERROR", "CONNECTION_TIMEOUT", "TUN_SETUP_FAILED", "TUN_IFACE_CREATE",
            "DISCONNECTED", "RECONNECTING", "CLIENT_SETUP", "NEED_CREDS"
        };
        for (const char *name : allowed) {
            if (event.name == name) {
                if (events.size() < 32) events.push_back(name); else eventsDropped = true;
                break;
            }
        }
        if (event.name == "CONNECTED") {
            if (dataSession()) { connectedInDataMode = true; return; } // expected in data mode
            unexpectedConnected = true; stop();
        }
        if (event.error || event.fatal || event.name == "RECONNECTING" || event.name == "DYNAMIC_CHALLENGE" || event.name == "AUTH_PENDING") stop();
    }
};
