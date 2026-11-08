import Foundation

/// Observed finance-homepage evidence for the standalone acceptance run.
/// Written by the orchestration after driving the real page; the session
/// receipt cites it only when it validates. No names, IDs or account data.
public struct FinanceHomepageObservation: Codable, Sendable {
    public let windowTitle: String
    public let criteria: [String: Bool]
    public let afterExplicitReload: Bool
    public let onCurrentSpace: Bool
    public let loggedIn: Bool
    public let loginFormPresent: Bool
    public let officialGUIRunning: Bool
    public let sensitiveFieldsRecorded: Bool
    public let observedAt: String?

    public static let criteriaNames = ["常用应用", "财务查询系统", "网上报账系统",
                                       "网上申报系统", "项目授权", "审批系统", "个人信息"]
    public static let expectedTitle = "智慧财务网上综合服务平台"

    public var validated: Bool {
        windowTitle == Self.expectedTitle
            && Self.criteriaNames.allSatisfy { criteria[$0] == true }
            && afterExplicitReload && onCurrentSpace && loggedIn
            && !loginFormPresent && !officialGUIRunning && !sensitiveFieldsRecorded
    }
}
