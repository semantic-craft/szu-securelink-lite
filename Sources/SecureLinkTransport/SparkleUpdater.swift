import Foundation
import SecureLinkCore

/// Sparkle 2.x EdDSA auto-update configuration, appcast entry validator,
/// human-readable numeric formatters, and 4-slot menu bar pin persistence.
public struct SparkleConfiguration: Codable, Sendable, Equatable {
    public static let defaultFeedURL = "https://securelink.szu.edu.cn/updates/appcast.xml"
    public static let defaultPublicEDKey = "MCowBQYDK2VwAyEAszuSecureLinkEd25519PubKey01="
    public static let maximumPackageBytes: UInt64 = 524_288_000
    public static let maximumLatencyMilliseconds: Int = 60_000
    public static let maximumRouteCount: Int = 512

    public let feedURL: String
    public let publicEDKey: String
    public let automaticChecks: Bool
    public let checkIntervalHours: Int

    public static let current = SparkleConfiguration(
        feedURL: defaultFeedURL,
        publicEDKey: defaultPublicEDKey,
        automaticChecks: true,
        checkIntervalHours: 24
    )

    public init(feedURL: String, publicEDKey: String, automaticChecks: Bool, checkIntervalHours: Int) {
        self.feedURL = feedURL
        self.publicEDKey = publicEDKey
        self.automaticChecks = automaticChecks
        self.checkIntervalHours = checkIntervalHours
    }

    public var isValid: Bool {
        feedURL.hasPrefix("https://")
            && BackendResources.validURL(feedURL)
            && publicEDKey.trimmingCharacters(in: .whitespacesAndNewlines).utf8.count >= 32
            && (1...168).contains(checkIntervalHours)
    }
}

public struct SparkleAppcastEntry: Codable, Sendable, Equatable {
    public let version: String
    public let buildNumber: Int
    public let downloadURL: String
    public let edSignature: String
    public let lengthBytes: UInt64
    public let releaseNotesZh: String
    public let releaseNotesEn: String

    public init(
        version: String,
        buildNumber: Int,
        downloadURL: String,
        edSignature: String,
        lengthBytes: UInt64,
        releaseNotesZh: String,
        releaseNotesEn: String
    ) {
        self.version = version
        self.buildNumber = buildNumber
        self.downloadURL = downloadURL
        self.edSignature = edSignature
        self.lengthBytes = lengthBytes
        self.releaseNotesZh = releaseNotesZh
        self.releaseNotesEn = releaseNotesEn
    }

    public var isValid: Bool {
        SparkleNumericFormatter.parseSemanticVersion(version) != nil
            && buildNumber > 0
            && downloadURL.hasPrefix("https://")
            && BackendResources.validURL(downloadURL)
            && SparkleNumericFormatter.validEd25519Signature(edSignature)
            && SparkleNumericFormatter.formatPackageSizeMB(lengthBytes) != nil
    }
}

public enum SparkleNumericFormatter {
    public static func parseSemanticVersion(_ raw: String) -> (Int, Int, Int)? {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        let clean = trimmed.hasPrefix("v") ? String(trimmed.dropFirst()) : trimmed
        let parts = clean.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3,
              let major = Int(parts[0]), major >= 0,
              let minor = Int(parts[1]), minor >= 0,
              let patch = Int(parts[2]), patch >= 0 else {
            return nil
        }
        return (major, minor, patch)
    }

    public static func isNewerVersion(current: String, candidate: String) -> Bool {
        guard let cur = parseSemanticVersion(current),
              let cand = parseSemanticVersion(candidate) else {
            return false
        }
        return cand > cur
    }

    public static func validEd25519Signature(_ raw: String) -> Bool {
        let clean = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard clean.utf8.count == 88, clean.hasSuffix("==") else { return false }
        return clean.dropLast(2).allSatisfy {
            $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "+" || $0 == "/")
        }
    }

    public static func formatPackageSizeMB(_ bytes: UInt64) -> String? {
        guard bytes > 0, bytes <= SparkleConfiguration.maximumPackageBytes else { return nil }
        let tenths = max(1, ((bytes * 10) + 524_288) / 1_048_576)
        return "\(tenths / 10).\(tenths % 10) MB"
    }

    public static func formatLatencyMilliseconds(_ ms: Int) -> String? {
        guard (1...SparkleConfiguration.maximumLatencyMilliseconds).contains(ms) else { return nil }
        return "\(ms) ms"
    }

    public static func formatDurationHuman(seconds: Int, english: Bool = false) -> String {
        let clamped = max(0, seconds)
        let totalMinutes = max(1, clamped / 60)
        let hours = totalMinutes / 60
        let minutes = totalMinutes % 60
        if hours == 0 {
            return english ? "\(minutes) min" : "\(minutes) 分钟"
        } else if minutes == 0 {
            return english ? "\(hours) hr" : "\(hours) 小时"
        } else {
            return english ? "\(hours) hr \(minutes) min" : "\(hours) 小时 \(minutes) 分钟"
        }
    }

    public static func formatRouteCount(_ count: Int, english: Bool = false) -> String? {
        guard (1...SparkleConfiguration.maximumRouteCount).contains(count) else { return nil }
        return english ? "\(count) campus routes" : "\(count) 条校内路由"
    }
}

/// Manages the 4 user-pinned campus shortcuts displayed in the macOS menu bar popover.
public enum MenuBarPinStore {
    public static let slotCount = 4
    public static let defaultPinnedIDs: [String] = [
        "szu-reimburse-system",
        "szu-finance-sso",
        "szu-cnki-sso",
        "szu-ehall"
    ]

    public static func normalize(_ candidateIDs: [String], available: [CampusShortcut]) -> [String] {
        let validIDs = Set(available.map(\.id))
        var result: [String] = []
        for id in candidateIDs where validIDs.contains(id) && !result.contains(id) {
            result.append(id)
            if result.count == slotCount { return result }
        }
        for fallback in defaultPinnedIDs where validIDs.contains(fallback) && !result.contains(fallback) {
            result.append(fallback)
            if result.count == slotCount { return result }
        }
        for item in available where !result.contains(item.id) {
            result.append(item.id)
            if result.count == slotCount { return result }
        }
        return result
    }

    public static func togglePin(id: String, current: [String], available: [CampusShortcut]) -> [String] {
        var pins = normalize(current, available: available)
        guard available.contains(where: { $0.id == id }) else { return pins }
        if let index = pins.firstIndex(of: id) {
            guard pins.count > 1 else { return pins }
            pins.remove(at: index)
            return pins
        }
        if pins.count >= slotCount {
            pins.removeLast()
        }
        pins.append(id)
        return pins
    }

    public static func load(from fileURL: URL, available: [CampusShortcut]) -> [String] {
        guard let data = try? Data(contentsOf: fileURL),
              data.count <= 4096,
              let decoded = try? JSONDecoder().decode([String].self, from: data) else {
            return normalize(defaultPinnedIDs, available: available)
        }
        return normalize(decoded, available: available)
    }

    public static func save(_ pinnedIDs: [String], to fileURL: URL) {
        let bounded = Array(pinnedIDs.prefix(slotCount))
        guard let data = try? JSONEncoder().encode(bounded) else { return }
        let directory = fileURL.deletingLastPathComponent()
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try? data.write(to: fileURL, options: .atomic)
    }
}
