#pragma once
#include <openvpn/tun/builder/base.hpp>
#include <openvpn/common/options.hpp>
#include "../ctrl-policy/parser.hpp"
#include <arpa/inet.h>
#include <cstdint>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

// A capture of upstream callbacks, NOT an executable or approved network plan.
// No filesystem, interface, route, DNS, socket, or OS configuration operations.
class MemoryTunPlan final : public openvpn::TunBuilderBase {
    struct Remote { std::string address; bool ipv6; };
    struct Address { std::string address, gateway; int prefix; bool ipv6, net30; };
    struct Route { std::string address; int prefix, metric; bool ipv6; };
    struct Redirect { bool ipv4, ipv6; unsigned flags; };
    struct DNSAddress { std::string address; unsigned port; };
    struct DNSServer { int priority; std::vector<DNSAddress> addresses; std::vector<std::string> domains; };
    struct DNS { bool fromDHCP; std::vector<std::string> search; std::vector<DNSServer> servers; };
    bool started = false, sealed = false, complete = false, nameDiscarded = false;
    bool domainCaptured = false, ctrlCaptured = false;
    securelink::ctrl::Snapshot ctrlPolicy;
    std::vector<std::string> domainOptions;
    const char *failure = nullptr;
    std::optional<int> layer, mtu;
    std::optional<Remote> remote;
    std::vector<Address> addresses;
    std::vector<Route> routes, excluded;
    int routeMetric = -1;
    bool metricSet = false;
    std::optional<Redirect> redirect;
    std::optional<DNS> dns;
    std::optional<bool> allow4, allow6, localDNS;
    bool writable() { return started && !sealed && !failure ? true : reject("invalid-sequence"); }
    static const char *boolean(bool value) { return value ? "true" : "false"; }
    static bool ip(const std::string &text, bool ipv6) {
        if (text.empty() || text.size() > 45 || text.find('\0') != std::string::npos) return false;
        in6_addr buffer{};
        return inet_pton(ipv6 ? AF_INET6 : AF_INET, text.c_str(), &buffer) == 1;
    }
    static bool anyIP(const std::string &text) { return ip(text, false) || ip(text, true); }
    static bool prefix(int value, bool ipv6) { return value >= 0 && value <= (ipv6 ? 128 : 32); }
    static bool domain(const std::string &text) {
        if (text.empty() || text.size() > 253) return false;
        std::size_t label = 0;
        for (std::size_t i = 0; i < text.size(); ++i) {
            const unsigned char c = text[i];
            if (c == '.') { if (!label || label > 63 || text[i-1] == '-') return false; label = 0; }
            else {
                if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-')) return false;
                if (!label && c == '-') return false;
                ++label;
            }
        }
        return label > 0 && label <= 63 && text.back() != '-';
    }
    bool addRoute(std::vector<Route> &target, const std::string &address, int length, int metric, bool ipv6) {
        if (!writable()) return false;
        if (target.size() >= 64) return reject("plan-limit");
        if (!ip(address, ipv6) || !prefix(length, ipv6) || metric < -1) return reject("invalid-route");
        target.push_back({address, length, metric, ipv6}); return true;
    }
    template<class T> static void scalar(std::ostream &out, const std::optional<T> &value) {
        if (value) out << *value; else out << "null";
    }
    static void flag(std::ostream &out, const std::optional<bool> &value) {
        if (value) out << boolean(*value); else out << "null";
    }
    static void strings(std::ostream &out, const std::vector<std::string> &values) {
        out << '['; for (std::size_t i = 0; i < values.size(); ++i) out << (i ? ",\"" : "\"") << values[i] << '"'; out << ']';
    }
public:
    bool capture_domain_options(const openvpn::OptionList &options) {
        if (!writable()) return false;
        if (domainCaptured) return reject("unsupported-domain-policy");
        try {
            securelink::ctrl::Options ctrl;
            if (const auto *rows = options.get_index_ptr("ctrl")) {
                if (rows->size() > securelink::ctrl::maximumOptions) return reject("plan-limit");
                for (const auto index : *rows) {
                    const auto &source = options[index];
                    if (source.size() > securelink::ctrl::maximumArguments + 1) return reject("plan-limit");
                    securelink::ctrl::Option row;
                    for (std::size_t i=0; i<source.size(); ++i) row.push_back(source.get(i, 513));
                    ctrl.push_back(std::move(row));
                }
            }
            try { ctrlPolicy = securelink::ctrl::parse(ctrl); ctrlCaptured = true; }
            catch (const securelink::ctrl::Invalid &e) {
                return reject(e.failure == securelink::ctrl::Failure::Limit ? "plan-limit" : "unsupported-control-policy");
            }
            const auto *indices = options.get_index_ptr("domain");
            if (indices && indices->size() > 64) return reject("plan-limit");
            if (indices) for (const auto index : *indices) {
                const auto &option = options[index];
                if (option.size() != 2) return reject("unsupported-domain-policy");
                const auto value = option.get(1, 256);
                const auto offset = value.rfind("*.", 0) == 0 ? 2 : (value.rfind(".", 0) == 0 ? 1 : 0);
                if (value.size() > 253 || !domain(value.substr(offset))) return reject("unsupported-domain-policy");
                domainOptions.push_back(value); // preserve exact form; not routing authorization
            }
            domainCaptured = true; return true;
        } catch (...) { return reject("unsupported-domain-policy"); }
    }
    bool reject(const char *reason) { if (!failure) failure = reason; complete = false; return false; }
    bool requested() const { return started; }
    bool isComplete() const { return complete; }
    std::string primaryIPv4Address() const {
        for (const auto &a : addresses) {
            if (!a.ipv6 && !a.address.empty()) return a.address;
        }
        return {};
    }
    std::string primaryDNSServerIPv4() const {
        if (!dns) return {};
        for (const auto &s : dns->servers) {
            for (const auto &a : s.addresses) {
                if (ip(a.address, false)) return a.address;
            }
        }
        return {};
    }
    std::string remoteAddress() const {
        return remote ? remote->address : std::string{};
    }
    bool hasRoute(const std::string &address, int prefix) const {
        for (const auto &r : routes) {
            if (!r.ipv6 && r.address == address && r.prefix == prefix) return true;
        }
        for (const auto &a : addresses) {
            if (!a.ipv6 && a.address == address && prefix == 32) return true;
        }
        return false;
    }
    bool tun_builder_new() override {
        if (started || sealed) return reject("invalid-sequence");
        started = true; return true;
    }
    bool tun_builder_set_layer(int value) override {
        if (!writable()) return false;
        if (layer || value != 3) return reject("unsupported-layer");
        layer = value; return true;
    }
    bool tun_builder_set_remote_address(const std::string &address, bool ipv6) override {
        if (!writable()) return false;
        if (remote || !ip(address, ipv6)) return reject("invalid-remote");
        remote = Remote{address, ipv6}; return true;
    }
    bool tun_builder_add_address(const std::string &address, int length, const std::string &gateway, bool ipv6, bool net30) override {
        if (!writable()) return false;
        if (addresses.size() >= 8) return reject("plan-limit");
        if (!ip(address, ipv6) || !prefix(length, ipv6) || (!gateway.empty() && !ip(gateway, ipv6)) || (ipv6 && net30)) return reject("invalid-address");
        addresses.push_back({address, gateway, length, ipv6, net30}); return true;
    }
    bool tun_builder_set_route_metric_default(int metric) override {
        if (!writable()) return false;
        if (metricSet || !routes.empty() || !excluded.empty() || metric < -1) return reject("invalid-route-metric");
        metricSet = true; routeMetric = metric; return true;
    }
    bool tun_builder_add_route(const std::string &address, int length, int metric, bool ipv6) override {
        return addRoute(routes, address, length, metric, ipv6);
    }
    bool tun_builder_exclude_route(const std::string &address, int length, int metric, bool ipv6) override {
        return addRoute(excluded, address, length, metric, ipv6);
    }
    bool tun_builder_reroute_gw(bool ipv4, bool ipv6, unsigned flags) override {
        if (!writable()) return false;
        // RG flags bits 0..9 plus RGWFlags::EmulateExcludeRoutes (16).
        if (redirect || (flags & ~0x103ffu)) return reject("unsupported-redirect-flags");
        redirect = Redirect{ipv4, ipv6, flags}; return true;
    }
    bool tun_builder_set_mtu(int value) override {
        if (!writable()) return false;
        if (mtu || value < 68 || value > 65535) return reject("invalid-mtu");
        mtu = value; return true;
    }
    bool tun_builder_set_dns_options(const openvpn::DnsOptions &input) override {
        if (!writable()) return false;
        if (dns) return reject("duplicate-dns");
        if (input.servers.size() > 8) return reject("plan-limit");
        DNS value{input.from_dhcp_options, {}, {}};
        std::size_t domainCount = 0;
        auto domains = [&](const std::vector<openvpn::DnsDomain> &source, std::vector<std::string> &target) {
            for (const auto &entry : source) {
                if (++domainCount > 32) return reject("plan-limit");
                if (!domain(entry.domain)) return reject("invalid-dns-domain");
                target.push_back(entry.domain);
            }
            return true;
        };
        if (!domains(input.search_domains, value.search)) return false;
        for (const auto &[priority, entry] : input.servers) {
            using S = openvpn::DnsServer;
            if ((entry.transport != S::Transport::Unset && entry.transport != S::Transport::Plain)
                || (entry.dnssec != S::Security::Unset && entry.dnssec != S::Security::No) || !entry.sni.empty()) return reject("unsupported-dns");
            if (entry.addresses.empty()) return reject("invalid-dns-address");
            if (entry.addresses.size() > 8) return reject("plan-limit");
            DNSServer server{priority, {}, {}};
            for (const auto &address : entry.addresses) {
                if (!anyIP(address.address) || address.port > 65535) return reject("invalid-dns-address");
                server.addresses.push_back({address.address, address.port});
            }
            if (!domains(entry.domains, server.domains)) return false;
            value.servers.push_back(std::move(server));
        }
        dns = std::move(value); return true;
    }
    bool tun_builder_set_session_name(const std::string &) override { if (!writable()) return false; nameDiscarded = true; return true; }
    bool tun_builder_set_allow_family(int af, bool allow) override {
        if (!writable()) return false;
        if (af != AF_INET && af != AF_INET6) return reject("unsupported-family");
        auto &field = af == AF_INET ? allow4 : allow6;
        if (field) return reject("duplicate-family"); field = allow; return true;
    }
    bool tun_builder_set_allow_local_dns(bool allow) override {
        if (!writable()) return false;
        if (localDNS) return reject("duplicate-local-dns"); localDNS = allow; return true;
    }
    bool tun_builder_add_proxy_bypass(const std::string &) override { return reject("unsupported-proxy"); }
    bool tun_builder_set_proxy_auto_config_url(const std::string &) override { return reject("unsupported-proxy"); }
    bool tun_builder_set_proxy_http(const std::string &, int) override { return reject("unsupported-proxy"); }
    bool tun_builder_set_proxy_https(const std::string &, int) override { return reject("unsupported-proxy"); }
    bool tun_builder_add_wins_server(const std::string &) override { return reject("unsupported-wins"); }
    std::vector<std::string> tun_builder_get_local_networks(bool) override { reject("unsupported-local-networks"); return {}; }
    bool tun_builder_persist() override { return false; }
    void tun_builder_establish_lite() override { reject("unsupported-persistence"); }
    int tun_builder_establish() override {
        if (!writable()) return -1;
        // Upstream TunProp::Config defaults MTU to zero and deliberately omits
        // set_mtu when unspecified. null preserves that fact, not an effective MTU.
        if (!layer || !remote || addresses.empty() || !domainCaptured || !ctrlCaptured) reject("incomplete-plan");
        sealed = true; complete = !failure; return -1;
    }
    // Unit-4 delta capture: this plan's base fields (layer, remote, addresses,
    // mtu and the policy captures) with routes replaced by an in-session push.
    // The returned capture is sealed; isComplete() false means the base was
    // never complete or a pushed route was rejected, and the caller must not
    // submit it. Pure capture construction; applying it is the executor's job.
    MemoryTunPlan delta_with_routes(const std::vector<std::pair<std::string, int>> &pushed) const {
        MemoryTunPlan delta;
        if (!complete || !remote || addresses.empty() || !layer.has_value()) return delta;
        delta.tun_builder_new();
        delta.capture_domain_options(openvpn::OptionList{});
        delta.tun_builder_set_layer(*layer);
        delta.tun_builder_set_remote_address(remote->address, remote->ipv6);
        for (const auto &a : addresses)
            delta.tun_builder_add_address(a.address, a.prefix, a.gateway, a.ipv6, a.net30);
        if (mtu) delta.tun_builder_set_mtu(*mtu);
        for (const auto &r : pushed) delta.tun_builder_add_route(r.first, r.second, -1, false);
        delta.tun_builder_establish();
        return delta;
    }
    std::string json() const {
        std::ostringstream out;
        out << "{\"version\":2,\"complete\":" << boolean(complete) << ",\"failure\":";
        if (failure) out << '"' << failure << '"'; else out << "null";
        out << ",\"layer\":"; scalar(out, layer); out << ",\"mtu\":"; scalar(out, mtu);
        out << ",\"remote\":";
        if (remote) out << "{\"address\":\"" << remote->address << "\",\"ipv6\":" << boolean(remote->ipv6) << '}'; else out << "null";
        out << ",\"addresses\":[";
        for (std::size_t i = 0; i < addresses.size(); ++i) {
            const auto &a = addresses[i];
            out << (i ? "," : "") << "{\"address\":\"" << a.address << "\",\"prefixLength\":" << a.prefix
                << ",\"gateway\":\"" << a.gateway << "\",\"ipv6\":" << boolean(a.ipv6) << ",\"net30\":" << boolean(a.net30) << '}';
        }
        out << ']';
        auto routeArray = [&](const char *key, const std::vector<Route> &items) {
            out << ",\"" << key << "\":[";
            for (std::size_t i = 0; i < items.size(); ++i) {
                const auto &r = items[i];
                out << (i ? "," : "") << "{\"address\":\"" << r.address << "\",\"prefixLength\":" << r.prefix
                    << ",\"metric\":" << r.metric << ",\"ipv6\":" << boolean(r.ipv6) << '}';
            }
            out << ']';
        };
        routeArray("routes", routes); routeArray("excludedRoutes", excluded);
        out << ",\"routeMetricDefault\":" << routeMetric << ",\"redirect\":";
        if (redirect) out << "{\"ipv4\":" << boolean(redirect->ipv4) << ",\"ipv6\":" << boolean(redirect->ipv6) << ",\"flags\":" << redirect->flags << '}'; else out << "null";
        out << ",\"dns\":";
        if (dns) {
            out << "{\"fromDhcp\":" << boolean(dns->fromDHCP) << ",\"searchDomains\":"; strings(out, dns->search);
            out << ",\"servers\":[";
            for (std::size_t i = 0; i < dns->servers.size(); ++i) {
                const auto &s = dns->servers[i]; out << (i ? "," : "") << "{\"priority\":" << s.priority << ",\"addresses\":[";
                for (std::size_t j = 0; j < s.addresses.size(); ++j) out << (j ? "," : "") << "{\"address\":\"" << s.addresses[j].address << "\",\"port\":" << s.addresses[j].port << '}';
                out << "],\"domains\":"; strings(out, s.domains); out << '}';
            }
            out << "]}";
        } else out << "null";
        out << ",\"allowIPv4\":"; flag(out, allow4); out << ",\"allowIPv6\":"; flag(out, allow6); out << ",\"allowLocalDNS\":"; flag(out, localDNS);
        out << ",\"domainOptionsCaptured\":" << boolean(domainCaptured) << ",\"domainOptions\":"; strings(out, domainOptions);
        out << ",\"ctrlOptionsCaptured\":" << boolean(ctrlCaptured)
            << ",\"ctrlOptionCount\":" << ctrlPolicy.optionCount
            << ",\"ctrlDuplicateKeys\":" << ctrlPolicy.duplicateKeys
            << ",\"ctrlDuplicateDomains\":" << ctrlPolicy.duplicateDomains
            << ",\"ctrlMappings\":[";
        for (std::size_t i=0; i<ctrlPolicy.mappings.size(); ++i) {
            const auto &mapping = ctrlPolicy.mappings[i];
            out << (i ? "," : "") << "{\"domain\":\"" << mapping.domain << "\",\"addresses\":";
            strings(out, mapping.addresses); out << ",\"addressPolicy\":\"any\"}";
        }
        out << ']';
        out << ",\"sessionNameDiscarded\":" << boolean(nameDiscarded) << '}';
        return out.str();
    }
};
