import Foundation
import XCTest
@testable import SecureLinkTransport

final class BackendResourcesTests: XCTestCase {
    private func body(_ list: [[String: Any]], returnCode: Int = 1) throws -> Data {
        var object: [String: Any] = ["returnCode": returnCode,
                                     "content": ["needTwoFactor": 0, "groupingSwitch": 1, "urlResourceList": list]]
        if returnCode != 1 { object["content"] = NSNull() }
        return try JSONSerialization.data(withJSONObject: object)
    }

    private func entry(id: String = "r1", name: String = "内部网", url: String = "https://www1.szu.edu.cn/") -> [String: Any] {
        ["id": id, "name": name, "url": url]
    }

    func testParseAcceptsBoundedWellFormedList() throws {
        let list = (0..<64).map { entry(id: "r\($0)", name: "资源\($0)", url: "https://host\($0).szu.edu.cn/") }
        let resources = try BackendResources.parse(try body(list))
        XCTAssertEqual(resources.count, 64)
        XCTAssertEqual(resources.first?.url, "https://host0.szu.edu.cn/")
    }

    func testEmptyListAndMissingOptionalFields() throws {
        XCTAssertEqual(try BackendResources.parse(try body([])).count, 0)
        var entry = self.entry()
        entry["icon"] = "svg-icon-neiwang"  // unknown fields tolerated
        entry["collected"] = true
        let resources = try BackendResources.parse(try body([entry]))
        XCTAssertEqual(resources.first?.name, "内部网")
    }

    func testStructuralRejections() throws {
        XCTAssertThrowsError(try BackendResources.parse(try body([], returnCode: 0)))  // rejected return code
        let oversized = (0..<65).map { entry(id: "r\($0)", url: "https://h\($0).example/") }
        XCTAssertThrowsError(try BackendResources.parse(try body(oversized)))
        XCTAssertThrowsError(try BackendResources.parse(Data("not json".utf8)))
        XCTAssertThrowsError(try BackendResources.parse(Data("<html/>".utf8)))
    }

    func testMalformedEntriesAreSkippedNotFatal() throws {
        let list = [
            entry(id: "", url: "https://a.example/"),                      // empty id skipped
            entry(id: "ok1", name: "内部网", url: "https://www1.szu.edu.cn/"),
            entry(id: "ok2", name: "OA", url: "ftp://nope/"),               // bad scheme skipped
            entry(id: "ok1", name: "dup", url: "https://d.example/"),       // duplicate id skipped
        ]
        let resources = try BackendResources.parse(try body(list))
        XCTAssertEqual(resources.map(\.id), ["ok1"])
    }

    func testURLSchemeAndLengthBounds() throws {
        XCTAssertFalse(BackendResources.validURL("javascript:alert(1)"))
        XCTAssertFalse(BackendResources.validURL("https://"))
        XCTAssertFalse(BackendResources.validURL(String(repeating: "h", count: 2049) + "/"))
        XCTAssertTrue(BackendResources.validURL("http://cwpt.szu.edu.cn:6090/login"))
    }

    func testFetchInputBoundsRejectBeforeNetwork() {
        XCTAssertThrowsError(try BackendResources.validateFetchInput(org: "", username: "u", deviceId: "d", system: "3"))
        XCTAssertThrowsError(try BackendResources.validateFetchInput(org: "szu", username: "u", deviceId: "d", system: String(repeating: "3", count: 33)))
        XCTAssertNoThrow(try BackendResources.validateFetchInput(org: "szu", username: "user", deviceId: "device-1", system: "3"))
    }

    func testOfficialApplicationListAndIndexUrlDecoding() throws {
        let object: [String: Any] = [
            "returnCode": 1,
            "content": [
                "needTwoFactor": 0,
                "groupingSwitch": 0,
                "applicationList": [
                    [
                        "id": "app-intranet",
                        "nameZh": "内部网",
                        "nameEn": "Intranet",
                        "indexUrl": "http://www1.szu.edu.cn/",
                        "type": "WEB",
                        "logo": "https://sheetaapi.wangsu.com/logo/intranet.png"
                    ],
                    [
                        "id": "app-oa",
                        "name": "OA",
                        "indexUrl": "http://oa.szu.edu.cn/login",
                        "type": "WEB"
                    ]
                ]
            ]
        ]
        let data = try JSONSerialization.data(withJSONObject: object)
        let resources = try BackendResources.parse(data)
        XCTAssertEqual(resources, [
            BackendUrlResource(
                id: "app-intranet",
                name: "内部网",
                url: "http://www1.szu.edu.cn/",
                type: "WEB",
                logo: "https://sheetaapi.wangsu.com/logo/intranet.png"
            ),
            BackendUrlResource(
                id: "app-oa",
                name: "OA",
                url: "http://oa.szu.edu.cn/login",
                type: "WEB",
                logo: nil
            )
        ])
        XCTAssertEqual(BackendResources.extractHosts(from: resources), ["www1.szu.edu.cn", "oa.szu.edu.cn"])
    }

    func testCampusShortcutsDefaultSSOAndNestedHostExtraction() throws {
        let defaults = CampusShortcuts.defaultShortcuts
        for shortcut in defaults {
            XCTAssertTrue(BackendResources.validURL(shortcut.url), "Invalid shortcut URL: \(shortcut.id)")
        }
        let finance = try XCTUnwrap(defaults.first { $0.id == "szu-finance-sso" })
        XCTAssertTrue(finance.isFavorite)
        XCTAssertEqual(finance.url, "https://authserver.szu.edu.cn/authserver/login?service=http%3A%2F%2Fcwpt.szu.edu.cn%3A6090%2Fapi%2Flogcas%2FcheckTicket")
        let reimburse = try XCTUnwrap(defaults.first { $0.id == "szu-reimburse-system" })
        XCTAssertTrue(reimburse.isFavorite)
        XCTAssertEqual(reimburse.url, "http://172.31.134.31/wsyy/frame_container.aspx")
        let cnki = try XCTUnwrap(defaults.first { $0.id == "szu-cnki-sso" })
        XCTAssertTrue(cnki.isFavorite)
        XCTAssertEqual(cnki.url, "https://fsso.cnki.net/Shibboleth.sso/Login?entityID=https://idp.szu.edu.cn/idp/shibboleth&target=https://fsso.cnki.net/secure/default.aspx")

        let hein = try XCTUnwrap(defaults.first { $0.id == "szu-heinonline" })
        XCTAssertTrue(hein.isFavorite)
        let oxford = try XCTUnwrap(defaults.first { $0.id == "szu-oxford-scholarship" })
        XCTAssertTrue(oxford.isFavorite)
        let cambridge = try XCTUnwrap(defaults.first { $0.id == "szu-cambridge" })
        XCTAssertTrue(cambridge.isFavorite)
        let pkulaw = try XCTUnwrap(defaults.first { $0.id == "szu-pkulaw" })
        XCTAssertTrue(pkulaw.isFavorite)
        XCTAssertEqual(pkulaw.url, "http://ezproxy.lib.szu.edu.cn/login?url=https://www.pkulaw.com/")
        let wos = try XCTUnwrap(defaults.first { $0.id == "szu-wos" })
        XCTAssertTrue(wos.isFavorite)
        XCTAssertEqual(wos.url, "http://accproxy.lib.szu.edu.cn/login?url=https://www.webofscience.com/wos/woscc/basic-search")
        let westlaw = try XCTUnwrap(defaults.first { $0.id == "szu-westlaw" })
        XCTAssertTrue(westlaw.isFavorite)

        let hosts = CampusShortcuts.extractHosts(from: [finance, cnki, hein, oxford, cambridge, pkulaw, wos, westlaw])
        XCTAssertEqual(hosts, [
            "authserver.szu.edu.cn",
            "cwpt.szu.edu.cn",
            "fsso.cnki.net",
            "idp.szu.edu.cn",
            "heinonline.org",
            "oup-sp.sams-sigma.com",
            "www.cambridge.org",
            "ezproxy.lib.szu.edu.cn",
            "www.pkulaw.com",
            "accproxy.lib.szu.edu.cn",
            "www.webofscience.com",
            "signon.thomsonreuters.com",
            "www.westlaw.com"
        ])
    }

    func testCampusShortcutsPersistenceAndCustomEntry() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent("szu-shortcuts-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let fileURL = tempDir.appendingPathComponent("shortcuts.json")

        var items = CampusShortcuts.load(from: fileURL)
        XCTAssertEqual(items.count, CampusShortcuts.defaultShortcuts.count)

        let custom = try XCTUnwrap(CampusShortcuts.makeCustomShortcut(name: "教务部", url: "https://jwb.szu.edu.cn/"))
        items.append(custom)
        if let hrIdx = items.firstIndex(where: { $0.id == "szu-hr" }) {
            items[hrIdx].isFavorite = true
        }
        CampusShortcuts.save(items, to: fileURL)

        let reloaded = CampusShortcuts.load(
            from: fileURL,
            workbench: [
                BackendUrlResource(id: "1813583268556206", name: "内部网", url: "https://www1.szu.edu.cn"),
                BackendUrlResource(id: "new-app", name: "研究生选课", url: "http://ehall.szu.edu.cn/yjsxkapp")
            ]
        )
        XCTAssertEqual(reloaded.first(where: { $0.id == "szu-hr" })?.isFavorite, true)
        XCTAssertNotNil(reloaded.first(where: { $0.name == "教务部" && $0.url == "https://jwb.szu.edu.cn/" }))
        XCTAssertNotNil(reloaded.first(where: { $0.id == "workbench-new-app" && $0.name == "研究生选课" }))
    }

    func testAboutMetadataAndAttributionText() {
        let about = AboutMetadata.current
        XCTAssertEqual(about.appName, "SZU SecureLink")
        XCTAssertEqual(about.version, "0.2.0")
        XCTAssertEqual(about.organization, "szu")
        XCTAssertEqual(about.attributionText, "深圳大学法律人工智能实训实验室")
        XCTAssertTrue(about.updateStatusText.contains("0.2.0"))
    }

    func testSparkleConfigurationAndNumericFormatting() {
        let config = SparkleConfiguration.current
        XCTAssertTrue(config.isValid)
        XCTAssertTrue(config.feedURL.hasPrefix("https://"))
        XCTAssertEqual(SparkleNumericFormatter.formatPackageSizeMB(14_889_779), "14.2 MB")
        XCTAssertNil(SparkleNumericFormatter.formatPackageSizeMB(0))
        XCTAssertEqual(SparkleNumericFormatter.formatLatencyMilliseconds(18), "18 ms")
        XCTAssertNil(SparkleNumericFormatter.formatLatencyMilliseconds(0))
        XCTAssertEqual(SparkleNumericFormatter.formatDurationHuman(seconds: 2520, english: false), "42 分钟")
        XCTAssertEqual(SparkleNumericFormatter.formatDurationHuman(seconds: 2520, english: true), "42 min")
        XCTAssertEqual(SparkleNumericFormatter.formatRouteCount(129, english: false), "129 条校内路由")
        XCTAssertEqual(SparkleNumericFormatter.formatRouteCount(129, english: true), "129 campus routes")
    }

    func testMenuBarPinStoreFourSlotInvariant() {
        let available = CampusShortcuts.defaultShortcuts
        let normalized = MenuBarPinStore.normalize(["szu-intranet", "invalid-id"], available: available)
        XCTAssertEqual(normalized.count, 4)
        XCTAssertEqual(normalized.first, "szu-intranet")

        let toggled = MenuBarPinStore.togglePin(id: "szu-pkulaw", current: MenuBarPinStore.defaultPinnedIDs, available: available)
        XCTAssertEqual(toggled.count, 4)
        XCTAssertTrue(toggled.contains("szu-pkulaw"))
    }
}
