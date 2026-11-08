import Foundation
import SecureLinkCore

/// Workbench quick-access resources (unit 5: the official client's 内部网/OA
/// cards). REA spec: POST /networkApi/gcable/getApplications (vpn token)
/// returns {returnCode, content:{needTwoFactor, groupingSwitch,
/// applicationList:[{id, name, nameZh, nameEn, indexUrl, type, logo, ...}]}}
/// (and legacy fixture alias urlResourceList / url). Click behavior on the
/// vendor client waits for vpnState=connected and opens the URL in the browser.
public struct BackendUrlResource: Codable, Sendable, Equatable {
    public let id: String
    public let name: String
    public let url: String
    public let type: String?
    public let logo: String?

    public init(id: String, name: String, url: String, type: String? = nil, logo: String? = nil) {
        self.id = id
        self.name = name
        self.url = url
        self.type = type
        self.logo = logo
    }
}

public enum BackendResourcesError: Error, Sendable {
    case invalidResponse, rejected, tooLarge, invalidInput
}

public enum BackendResources {
    public static let maximumResources = 64

    public struct Response: Codable, Sendable {
        public let returnCode: Int
        public let content: Content?
        public struct Content: Codable, Sendable {
            public let needTwoFactor: Int?
            public let groupingSwitch: Int?
            public let applicationList: [RawResource]?
            public let urlResourceList: [RawResource]?
        }
        public struct RawResource: Codable, Sendable {
            public let id: String?
            public let name: String?
            public let nameZh: String?
            public let nameEn: String?
            public let indexUrl: String?
            public let url: String?
            public let type: String?
            public let logo: String?
        }
    }

    /// Strict parse: bounded counts, string ids/names, http(s) urls only,
    /// unique ids; malformed single entries are skipped, structural problems
    /// reject the whole response.
    public static func parse(_ data: Data) throws -> [BackendUrlResource] {
        guard data.count <= BackendDiscovery.maximumResponse else { throw BackendResourcesError.tooLarge }
        let response: Response
        do { response = try JSONDecoder().decode(Response.self, from: data) }
        catch { throw BackendResourcesError.invalidResponse }
        guard response.returnCode == 1 else { throw BackendResourcesError.rejected }
        let raw = response.content?.applicationList ?? response.content?.urlResourceList ?? []
        guard raw.count <= maximumResources else { throw BackendResourcesError.invalidResponse }
        var resources: [BackendUrlResource] = []
        var seen: Set<String> = []
        for item in raw {
            let resolvedID = item.id?.trimmingCharacters(in: .whitespacesAndNewlines)
            let resolvedName = [item.nameZh, item.name, item.nameEn]
                .compactMap { $0?.trimmingCharacters(in: .whitespacesAndNewlines) }
                .first(where: { !$0.isEmpty })
            let resolvedURL = [item.indexUrl, item.url]
                .compactMap { $0?.trimmingCharacters(in: .whitespacesAndNewlines) }
                .first(where: { !$0.isEmpty })
            let resolvedType = item.type?.trimmingCharacters(in: .whitespacesAndNewlines)
            let resolvedLogo = item.logo?.trimmingCharacters(in: .whitespacesAndNewlines)
            guard let id = resolvedID, let name = resolvedName, let url = resolvedURL,
                  !id.isEmpty, id.utf8.count <= 64,
                  !name.isEmpty, name.utf8.count <= 128,
                  validURL(url), seen.insert(id).inserted else { continue }
            let cleanType = (resolvedType?.isEmpty == false && (resolvedType?.utf8.count ?? 0) <= 64) ? resolvedType : nil
            let cleanLogo = (resolvedLogo?.isEmpty == false && (resolvedLogo?.utf8.count ?? 0) <= 2048) ? resolvedLogo : nil
            resources.append(BackendUrlResource(id: id, name: name, url: url, type: cleanType, logo: cleanLogo))
        }
        return resources
    }

    static func validURL(_ text: String) -> Bool {
        guard !text.isEmpty, text.utf8.count <= 2048,
              text.utf8.allSatisfy({ (0x21...0x7E).contains($0) }),
              text.hasPrefix("http://") || text.hasPrefix("https://") else { return false }
        let rest = String(text.dropFirst(text.hasPrefix("https://") ? 8 : 7))
        guard let hostPort = rest.split(whereSeparator: { $0 == "/" || $0 == "?" || $0 == "#" }).first,
              let host = hostPort.split(separator: ":").first,
              !host.isEmpty else { return false }
        return hostPort.allSatisfy { $0.isLetter || $0.isNumber || $0 == "." || $0 == "-" || $0 == ":" || $0 == "[" || $0 == "]" }
    }

    /// Extracts distinct hostnames (without port) from validated resource URLs so
    /// in-tunnel DNS resolution can cover all workbench entry points.
    public static func extractHosts(from resources: [BackendUrlResource]) -> [String] {
        extractHostsFromURLStrings(resources.map(\.url))
    }

    public static func extractHostsFromURLStrings(_ urlStrings: [String]) -> [String] {
        var hosts: [String] = []
        var seen: Set<String> = []
        func appendValidHost(_ candidate: String?) {
            guard let host = candidate?.lowercased(), !host.isEmpty,
                  host.utf8.count <= 253,
                  host.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "." || $0 == "-" }),
                  seen.insert(host).inserted else { return }
            hosts.append(host)
        }
        for raw in urlStrings {
            guard let components = URLComponents(string: raw) else { continue }
            appendValidHost(components.host)
            // Also inspect nested CAS/SAML service= / url= / entityID= / target= / returnto= parameters
            // so direct SSO shortcuts pre-resolve both the gateway and target intranet hosts.
            for item in components.queryItems ?? [] where ["service", "url", "entityid", "target", "returnto"].contains(item.name.lowercased()) {
                if let nested = item.value, let nestedComponents = URLComponents(string: nested) {
                    appendValidHost(nestedComponents.host)
                }
            }
        }
        return hosts
    }

    /// Bounds validated synchronously so tests need no network stack.
    public static func validateFetchInput(org: String, username: String, deviceId: String, system: String) throws {
        guard (1...64).contains(org.utf8.count), (1...64).contains(username.utf8.count),
              (1...128).contains(deviceId.utf8.count), (1...32).contains(system.utf8.count) else {
            throw BackendResourcesError.invalidInput
        }
    }

    public static func fetch(material: BackendPublicMaterial, accessToken: String, org: String,
                             username: String, deviceId: String, system: String = "3",
                             serverScope: String? = nil,
                             configuration: URLSessionConfiguration? = nil) async throws -> [BackendUrlResource] {
        try validateFetchInput(org: org, username: username, deviceId: deviceId, system: system)
        let data = try await BackendDiscovery.request(material: material, operation: .getApplications,
            payload: ["org": org, "username": username, "deviceId": deviceId, "system": system],
            accessToken: accessToken, serverScope: serverScope, configuration: configuration)
        return try parse(data)
    }
}

/// Application metadata, update-check status, and subtle attribution for the About page.
public struct AboutMetadata: Codable, Sendable, Equatable {
    public let appName: String
    public let version: String
    public let build: String
    public let organization: String
    public let summary: String
    public let updateStatusText: String
    public let attributionText: String

    public static let current = AboutMetadata(
        appName: "SZU SecureLink",
        version: "0.2.0",
        build: "1",
        organization: "szu",
        summary: "深圳大学零信任校园网原生客户端（macOS Native · Safe Rust 核心）",
        updateStatusText: "当前已是最新版本（v0.2.0）",
        attributionText: "深圳大学法律人工智能实训实验室"
    )

    public init(
        appName: String,
        version: String,
        build: String,
        organization: String,
        summary: String,
        updateStatusText: String,
        attributionText: String
    ) {
        self.appName = appName
        self.version = version
        self.build = build
        self.organization = organization
        self.summary = summary
        self.updateStatusText = updateStatusText
        self.attributionText = attributionText
    }
}

/// Direct-jump campus service shortcut for the Workbench favorites bar.
/// Allows jumping straight into CAS-authenticated subsystems (such as the
/// Finance System checkTicket SSO entry) without first opening 内部网.
public struct CampusShortcut: Codable, Sendable, Equatable, Identifiable {
    public let id: String
    public var name: String
    public var subtitle: String
    public var url: String
    public var isFavorite: Bool
    public var isBuiltIn: Bool

    public init(id: String, name: String, subtitle: String, url: String, isFavorite: Bool, isBuiltIn: Bool = false) {
        self.id = id
        self.name = name
        self.subtitle = subtitle
        self.url = url
        self.isFavorite = isFavorite
        self.isBuiltIn = isBuiltIn
    }
}

public enum CampusShortcuts {
    public static let maximumShortcuts = 32

    /// Direct CAS SSO ticket-exchange URL for SZU Intelligent Finance Platform:
    /// hits authserver.szu.edu.cn with the active CAS session, issues a ticket to
    /// cwpt.szu.edu.cn:6090/api/logcas/checkTicket, and lands directly on /home
    /// without stopping at cwpt.szu.edu.cn:6090/login or requiring 内部网 first.
    public static let financeCASSingleSignOnURL =
        "https://authserver.szu.edu.cn/authserver/login?service=http%3A%2F%2Fcwpt.szu.edu.cn%3A6090%2Fapi%2Flogcas%2FcheckTicket"

    /// Direct SZU Online Self-Service Reimbursement System (深圳大学网上自助报账系统)
    /// inside the finance hall (routed via 172.31.134.31/32 over the zero-trust tunnel).
    public static let reimbursementSystemDirectURL =
        "http://172.31.134.31/wsyy/frame_container.aspx"

    /// Direct SZU Library -> CNKI institutional SSO entry (/er/access/16129 on
    /// www.lib.szu.edu.cn/er/cnki): authenticates via idp.szu.edu.cn SAML2 SSO
    /// and logs directly into cnki.net as "深圳大学" institutional user.
    public static let cnkiSZUInstitutionalLoginURL =
        "https://fsso.cnki.net/Shibboleth.sso/Login?entityID=https://idp.szu.edu.cn/idp/shibboleth&target=https://fsso.cnki.net/secure/default.aspx"

    /// Direct SZU Library -> HeinOnline institutional SSO entry (/er/access/18033 on
    /// www.lib.szu.edu.cn/er/heinonline): WAYFless Shibboleth via idp.szu.edu.cn.
    public static let heinOnlineSZUInstitutionalLoginURL =
        "https://heinonline.org/HOL/WAYFless?entityID=https://idp.szu.edu.cn/idp/shibboleth&target=https://heinonline.org/HOL/Welcome"

    /// Direct SZU Library -> Oxford Scholarship Online institutional SSO entry
    /// (www.lib.szu.edu.cn/er/oso & /er/ojc): SAML2 SSO via oup-sp.sams-sigma.com and idp.szu.edu.cn
    /// landing on Oxford Academic Books as "Shenzhen University".
    public static let oxfordScholarshipSZUInstitutionalLoginURL =
        "https://oup-sp.sams-sigma.com/Shibboleth.sso/Login?entityID=https://idp.szu.edu.cn/idp/shibboleth&target=https%3A%2F%2Foup-sp.sams-sigma.com/shib%3Fdest=https%3A%2F%2Facademic.oup.com%2FSHIBBOLETH?dest=%2Fbooks"

    /// Direct SZU Library -> Cambridge Core institutional SSO entry (/er/access/18322 on
    /// www.lib.szu.edu.cn/er/cjo): authenticates via idp.szu.edu.cn as "Shenzhen University".
    public static let cambridgeCoreSZUInstitutionalLoginURL =
        "https://www.cambridge.org/core/idp/SZU_93544"

    /// Direct SZU Library -> PKULaw (北大法宝) EZproxy institutional entry (/er/access/18337 on
    /// www.lib.szu.edu.cn/er/pkulaw): authenticates via SZU CAS -> ezproxy.lib.szu.edu.cn
    /// using unencoded url= parameter so EZproxy preserves qurl and logs into SZU institutional account.
    public static let pkulawSZUInstitutionalLoginURL =
        "http://ezproxy.lib.szu.edu.cn/login?url=https://www.pkulaw.com/"

    /// Direct SZU Library -> Web of Science Core Collection (SCIE/SSCI) dedicated proxy entry
    /// (/er/access/18854 on www.lib.szu.edu.cn/er/scie): authenticates via SZU CAS -> accproxy.lib.szu.edu.cn
    /// as "Shenzhen University".
    public static let webOfScienceSZUInstitutionalLoginURL =
        "http://accproxy.lib.szu.edu.cn/login?url=https://www.webofscience.com/wos/woscc/basic-search"

    /// Direct SZU Library -> Thomson Reuters Westlaw CARSI institutional federation entry
    /// (/er/access/18298 & /er/access/18299 on www.lib.szu.edu.cn/er/westlaw): authenticates
    /// institutional affiliation via idp.szu.edu.cn SAML2 SSO.
    public static let westlawSZUInstitutionalLoginURL =
        "https://signon.thomsonreuters.com/federation/CARSI?entityid=https://idp.szu.edu.cn/idp/shibboleth&returnto=https://www.westlaw.com"

    public static let defaultShortcuts: [CampusShortcut] = [
        CampusShortcut(
            id: "szu-finance-sso",
            name: "财务服务大厅",
            subtitle: "CAS 免登直达智慧财务综合服务平台",
            url: financeCASSingleSignOnURL,
            isFavorite: true,
            isBuiltIn: true
        ),
        CampusShortcut(
            id: "szu-reimburse-system",
            name: "网上报账系统",
            subtitle: "深圳大学网上自助报账系统（我的票夹/日常与差旅报销）",
            url: reimbursementSystemDirectURL,
            isFavorite: true,
            isBuiltIn: true
        ),
        CampusShortcut(
            id: "szu-cnki-sso",
            name: "中国知网（深大机构登录）",
            subtitle: "深大图书馆知网总库机构直达",
            url: cnkiSZUInstitutionalLoginURL,
            isFavorite: true,
            isBuiltIn: true
        ),
        CampusShortcut(
            id: "szu-heinonline",
            name: "HeinOnline",
            subtitle: "深大法学期刊与判例库机构直达",
            url: heinOnlineSZUInstitutionalLoginURL,
            isFavorite: true,
            isBuiltIn: true
        ),
        CampusShortcut(
            id: "szu-oxford-scholarship",
            name: "Oxford Scholarship",
            subtitle: "牛津学术专著电子书深大机构直达",
            url: oxfordScholarshipSZUInstitutionalLoginURL,
            isFavorite: true,
            isBuiltIn: true
        ),
        CampusShortcut(
            id: "szu-cambridge",
            name: "剑桥数据库（Cambridge Core）",
            subtitle: "剑桥期刊与电子书深大机构直达",
            url: cambridgeCoreSZUInstitutionalLoginURL,
            isFavorite: true,
            isBuiltIn: true
        ),
        CampusShortcut(
            id: "szu-pkulaw",
            name: "北大法宝",
            subtitle: "深大图书馆 EZproxy 机构直达",
            url: pkulawSZUInstitutionalLoginURL,
            isFavorite: true,
            isBuiltIn: true
        ),
        CampusShortcut(
            id: "szu-wos",
            name: "Web of Science",
            subtitle: "SCIE/SSCI 核心合集深大专道直达",
            url: webOfScienceSZUInstitutionalLoginURL,
            isFavorite: true,
            isBuiltIn: true
        ),
        CampusShortcut(
            id: "szu-westlaw",
            name: "Westlaw",
            subtitle: "Thomson Reuters Westlaw 深大机构直达",
            url: westlawSZUInstitutionalLoginURL,
            isFavorite: true,
            isBuiltIn: true
        ),
        CampusShortcut(
            id: "szu-intranet",
            name: "内部网（公文通）",
            subtitle: "深圳大学内部网与校园公文通",
            url: "https://www1.szu.edu.cn/",
            isFavorite: true,
            isBuiltIn: true
        ),
        CampusShortcut(
            id: "szu-oa",
            name: "OA 系统",
            subtitle: "深圳大学协同办公系统",
            url: "http://210.39.3.155:9090/goLogin.do",
            isFavorite: true,
            isBuiltIn: true
        ),
        CampusShortcut(
            id: "szu-ehall",
            name: "办事大厅（一网通办）",
            subtitle: "网上办事大厅 ehall.szu.edu.cn",
            url: "https://ehall.szu.edu.cn/new/index.html",
            isFavorite: true,
            isBuiltIn: true
        ),
        CampusShortcut(
            id: "szu-library",
            name: "深大图书馆",
            subtitle: "深圳大学图书馆与数据库导航",
            url: "http://www.lib.szu.edu.cn/",
            isFavorite: true,
            isBuiltIn: true
        ),
        CampusShortcut(
            id: "szu-hr",
            name: "人力资源部",
            subtitle: "人事服务与考核系统",
            url: "http://hr.szu.edu.cn/",
            isFavorite: false,
            isBuiltIn: true
        ),
        CampusShortcut(
            id: "szu-skb",
            name: "社会科学部",
            subtitle: "人文社科科研管理",
            url: "http://skb.szu.edu.cn/",
            isFavorite: false,
            isBuiltIn: true
        ),
        CampusShortcut(
            id: "szu-mail",
            name: "教师邮箱",
            subtitle: "深圳大学教师电子邮箱",
            url: "https://mail.szu.edu.cn/",
            isFavorite: false,
            isBuiltIn: true
        )
    ]

    public static func extractHosts(from shortcuts: [CampusShortcut]) -> [String] {
        BackendResources.extractHostsFromURLStrings(shortcuts.map(\.url))
    }

    public static func mergeWithDefaults(saved: [CampusShortcut], workbench: [BackendUrlResource] = []) -> [CampusShortcut] {
        let savedByID = Dictionary(uniqueKeysWithValues: saved.map { ($0.id, $0) })
        var result: [CampusShortcut] = []
        var seenIDs: Set<String> = []
        var seenURLs: Set<String> = []

        for var item in defaultShortcuts {
            if let existing = savedByID[item.id] {
                item.isFavorite = existing.isFavorite
            }
            seenIDs.insert(item.id)
            seenURLs.insert(normalizedURLKey(item.url))
            result.append(item)
        }

        // Merge any extra server-pushed workbench resources not already covered by defaults.
        for resource in workbench {
            let key = normalizedURLKey(resource.url)
            guard !seenURLs.contains(key) else { continue }
            let id = "workbench-\(resource.id)"
            guard seenIDs.insert(id).inserted else { continue }
            seenURLs.insert(key)
            let isFav = savedByID[id]?.isFavorite ?? true
            result.append(CampusShortcut(
                id: id,
                name: resource.name,
                subtitle: "零信任工作台下发资源",
                url: resource.url,
                isFavorite: isFav,
                isBuiltIn: true
            ))
        }

        // Append user-added custom shortcuts that remain valid.
        for item in saved where !item.isBuiltIn {
            guard result.count < maximumShortcuts,
                  !item.id.isEmpty, item.id.utf8.count <= 64,
                  !item.name.isEmpty, item.name.utf8.count <= 128,
                  item.subtitle.utf8.count <= 128,
                  BackendResources.validURL(item.url),
                  seenIDs.insert(item.id).inserted else { continue }
            result.append(item)
        }
        return result
    }

    public static func makeCustomShortcut(name: String, subtitle: String = "自定义常用校内入口", url: String) -> CampusShortcut? {
        let cleanName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let cleanSubtitle = subtitle.trimmingCharacters(in: .whitespacesAndNewlines)
        let cleanURL = url.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleanName.isEmpty, cleanName.utf8.count <= 64,
              cleanSubtitle.utf8.count <= 128,
              BackendResources.validURL(cleanURL) else { return nil }
        return CampusShortcut(
            id: "custom-\(UUID().uuidString.lowercased())",
            name: cleanName,
            subtitle: cleanSubtitle.isEmpty ? "自定义常用校内入口" : cleanSubtitle,
            url: cleanURL,
            isFavorite: true,
            isBuiltIn: false
        )
    }

    public static func load(from fileURL: URL, workbench: [BackendUrlResource] = []) -> [CampusShortcut] {
        guard let data = try? Data(contentsOf: fileURL),
              data.count <= 65536,
              let decoded = try? JSONDecoder().decode([CampusShortcut].self, from: data) else {
            return mergeWithDefaults(saved: [], workbench: workbench)
        }
        return mergeWithDefaults(saved: decoded, workbench: workbench)
    }

    public static func save(_ shortcuts: [CampusShortcut], to fileURL: URL) {
        let bounded = Array(shortcuts.prefix(maximumShortcuts))
        guard let data = try? JSONEncoder().encode(bounded) else { return }
        let directory = fileURL.deletingLastPathComponent()
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try? data.write(to: fileURL, options: .atomic)
    }

    private static func normalizedURLKey(_ url: String) -> String {
        var trimmed = url.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        while trimmed.hasSuffix("/") { trimmed.removeLast() }
        return trimmed
    }
}
