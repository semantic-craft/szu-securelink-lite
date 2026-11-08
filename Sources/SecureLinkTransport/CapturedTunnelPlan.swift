import Foundation
import Darwin

/// Server callback data, never authorization to apply system configuration.
public struct CapturedTunnelPlan: Codable, Sendable {
    public struct Remote: Codable, Sendable { let address: String; let ipv6: Bool }
    public struct Address: Codable, Sendable {
        let address: String; let prefixLength: Int; let gateway: String; let ipv6: Bool; let net30: Bool
    }
    public struct Route: Codable, Sendable { let address: String; let prefixLength: Int; let metric: Int; let ipv6: Bool }
    public struct Redirect: Codable, Sendable { let ipv4: Bool; let ipv6: Bool; let flags: UInt32 }
    public struct DNSAddress: Codable, Sendable { let address: String; let port: UInt32 }
    public struct DNSServer: Codable, Sendable { let priority: Int; let addresses: [DNSAddress]; let domains: [String] }
    public struct DNS: Codable, Sendable { let fromDhcp: Bool; let searchDomains: [String]; let servers: [DNSServer] }
    public struct StaticMapping: Codable, Sendable { let domain: String; let addresses: [String]; let addressPolicy: String }
    public let ctrlOptionsCaptured: Bool
    public let ctrlOptionCount: Int
    public let ctrlDuplicateKeys: Int
    public let ctrlDuplicateDomains: Int
    public let ctrlMappings: [StaticMapping]
    public let version: Int
    public let domainOptionsCaptured: Bool
    public let domainOptions: [String]
    public let complete: Bool
    public let failure: String?
    let layer: Int?
    let mtu: Int?
    let remote: Remote?
    let addresses: [Address]
    let routes: [Route]
    let excludedRoutes: [Route]
    let routeMetricDefault: Int
    let redirect: Redirect?
    let dns: DNS?
    let allowIPv4: Bool?
    let allowIPv6: Bool?
    let allowLocalDNS: Bool?
    let sessionNameDiscarded: Bool

    private enum CodingKeys: String, CodingKey { case version, ctrlOptionsCaptured, ctrlOptionCount, ctrlDuplicateKeys, ctrlDuplicateDomains, ctrlMappings, domainOptionsCaptured, domainOptions, complete, failure, layer, mtu, remote, addresses, routes, excludedRoutes, routeMetricDefault, redirect, dns, allowIPv4, allowIPv6, allowLocalDNS, sessionNameDiscarded }
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(version, forKey: .version)
        try container.encode(ctrlOptionsCaptured, forKey: .ctrlOptionsCaptured)
        try container.encode(ctrlOptionCount, forKey: .ctrlOptionCount)
        try container.encode(ctrlDuplicateKeys, forKey: .ctrlDuplicateKeys)
        try container.encode(ctrlDuplicateDomains, forKey: .ctrlDuplicateDomains)
        try container.encode(ctrlMappings, forKey: .ctrlMappings)
        try container.encode(domainOptionsCaptured, forKey: .domainOptionsCaptured)
        try container.encode(domainOptions, forKey: .domainOptions)
        try container.encode(complete, forKey: .complete)
        try container.encode(failure, forKey: .failure)
        try container.encode(layer, forKey: .layer)
        try container.encode(mtu, forKey: .mtu)
        try container.encode(remote, forKey: .remote)
        try container.encode(addresses, forKey: .addresses)
        try container.encode(routes, forKey: .routes)
        try container.encode(excludedRoutes, forKey: .excludedRoutes)
        try container.encode(routeMetricDefault, forKey: .routeMetricDefault)
        try container.encode(redirect, forKey: .redirect)
        try container.encode(dns, forKey: .dns)
        try container.encode(allowIPv4, forKey: .allowIPv4)
        try container.encode(allowIPv6, forKey: .allowIPv6)
        try container.encode(allowLocalDNS, forKey: .allowLocalDNS)
        try container.encode(sessionNameDiscarded, forKey: .sessionNameDiscarded)
    }

    func validate() throws {
        let failures: Set<String> = ["invalid-sequence", "plan-limit", "invalid-route", "unsupported-layer",
            "invalid-remote", "invalid-address", "invalid-route-metric", "unsupported-redirect-flags",
            "invalid-mtu", "duplicate-dns", "invalid-dns-domain", "unsupported-dns", "invalid-dns-address",
            "unsupported-family", "duplicate-family", "duplicate-local-dns", "unsupported-proxy",
            "unsupported-wins", "unsupported-local-networks", "unsupported-persistence", "incomplete-plan", "unsupported-domain-policy", "unsupported-control-policy"]
        func ip(_ text: String, _ ipv6: Bool) -> Bool {
            guard !text.isEmpty, text.utf8.count <= 45, !text.contains("\0") else { return false }
            var buffer = in6_addr()
            return text.withCString { inet_pton(ipv6 ? AF_INET6 : AF_INET, $0, &buffer) } == 1
        }
        func domain(_ text: String) -> Bool {
            guard !text.isEmpty, text.utf8.count <= 253 else { return false }
            return text.split(separator: ".", omittingEmptySubsequences: false).allSatisfy { label in
                !label.isEmpty && label.utf8.count <= 63 && label.first != "-" && label.last != "-"
                    && label.utf8.allSatisfy { (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || $0 == 45 }
            }
        }
        func policyDomain(_ value: String) -> Bool {
            guard value.utf8.count <= 253 else { return false }
            let suffix = value.hasPrefix("*.") ? String(value.dropFirst(2)) : (value.hasPrefix(".") ? String(value.dropFirst()) : value)
            return domain(suffix)
        }
        func route(_ r: Route) -> Bool {
            ip(r.address, r.ipv6) && (0...(r.ipv6 ? 128 : 32)).contains(r.prefixLength)
                && (-1...Int(Int32.max)).contains(r.metric)
        }
        guard version == 2, (0...64).contains(ctrlOptionCount), (0...8192).contains(ctrlDuplicateKeys),
              (0...64).contains(ctrlDuplicateDomains), ctrlMappings.count <= ctrlOptionCount,
              ctrlMappings.count + ctrlDuplicateDomains == ctrlOptionCount,
              ctrlOptionsCaptured || (ctrlOptionCount == 0 && ctrlDuplicateKeys == 0),
              !complete || ctrlOptionsCaptured, Set(ctrlMappings.map(\.domain)).count == ctrlMappings.count,
              ctrlMappings.allSatisfy({ domain($0.domain) && $0.addressPolicy == "any"
                && (1...16).contains($0.addresses.count) && $0.addresses.allSatisfy({ ip($0, false) }) }), domainOptions.count <= 64, domainOptions.allSatisfy(policyDomain),
              domainOptionsCaptured || domainOptions.isEmpty, !complete || domainOptionsCaptured, failure == nil || failures.contains(failure!), !complete || failure == nil,
              layer == nil || layer == 3, mtu == nil || (68...65535).contains(mtu!),
              remote == nil || ip(remote!.address, remote!.ipv6),
              addresses.count <= 8, routes.count <= 64, excludedRoutes.count <= 64,
              addresses.allSatisfy({ ip($0.address, $0.ipv6) && (0...($0.ipv6 ? 128 : 32)).contains($0.prefixLength)
                && ($0.gateway.isEmpty || ip($0.gateway, $0.ipv6)) && !($0.ipv6 && $0.net30) }),
              routes.allSatisfy(route), excludedRoutes.allSatisfy(route),
              (-1...Int(Int32.max)).contains(routeMetricDefault),
              redirect == nil || redirect!.flags & ~0x103ff == 0,
              !complete || (layer != nil && remote != nil && !addresses.isEmpty) else {
            throw OpenVPNEvaluationError.invalidReceipt
        }
        if let dns {
            guard dns.servers.count <= 8,
                  dns.searchDomains.count + dns.servers.reduce(0, { $0 + $1.domains.count }) <= 32,
                  dns.searchDomains.allSatisfy(domain),
                  dns.servers.allSatisfy({ server in
                      (Int(Int32.min)...Int(Int32.max)).contains(server.priority)
                        && (1...8).contains(server.addresses.count) && server.domains.allSatisfy(domain)
                        && server.addresses.allSatisfy({ (ip($0.address, false) || ip($0.address, true)) && $0.port <= 65535 })
                  }) else { throw OpenVPNEvaluationError.invalidReceipt }
        }
        guard try JSONEncoder().encode(self).count <= 48 * 1024 else { throw OpenVPNEvaluationError.invalidReceipt }
    }
}
