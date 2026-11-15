import AppKit
import Combine
import Foundation
import XCTest
@testable import SecureLinkApp
@testable import SecureLinkCore
@testable import SecureLinkTransport

@MainActor
final class SecureLinkAppStateTests: XCTestCase {
    func testMenuBarStatusIconStaticIdentityAndTemplateContract() {
        let firstConnected = MenuBarStatusIcon.image(connected: true)
        let secondConnected = MenuBarStatusIcon.image(connected: true)
        let firstDisconnected = MenuBarStatusIcon.image(connected: false)
        let secondDisconnected = MenuBarStatusIcon.image(connected: false)

        XCTAssertTrue(firstConnected === secondConnected)
        XCTAssertTrue(firstDisconnected === secondDisconnected)
        XCTAssertTrue(firstConnected !== firstDisconnected)
        XCTAssertTrue(firstConnected.isTemplate)
        XCTAssertTrue(firstDisconnected.isTemplate)
        XCTAssertEqual(firstConnected.size, NSSize(width: 18, height: 18))
        XCTAssertEqual(firstDisconnected.size, NSSize(width: 18, height: 18))
    }

    func testShortcutCatalogStoreSinglePassInitValidationAndPersistence() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let shortcutsURL = tempDir.appendingPathComponent("shortcuts.json")
        let pinsURL = tempDir.appendingPathComponent("menubar-pins.json")

        let seededCustom = try XCTUnwrap(
            CampusShortcuts.makeCustomShortcut(name: "法学院", url: "https://law.szu.edu.cn/")
        )
        CampusShortcuts.save(CampusShortcuts.defaultShortcuts + [seededCustom], to: shortcutsURL)
        MenuBarPinStore.save([seededCustom.id, "szu-reimburse-system", "szu-finance-sso", "szu-cnki-sso"], to: pinsURL)

        let store = ShortcutCatalogStore(shortcutsURL: shortcutsURL, menuBarPinsURL: pinsURL)
        XCTAssertEqual(store.pinnedMenuBarIDs.first, seededCustom.id)
        XCTAssertEqual(store.menuBarPinnedShortcuts.first?.id, seededCustom.id)

        var changeCount = 0
        let cancellable = store.objectWillChange.sink { _ in changeCount += 1 }
        defer { cancellable.cancel() }

        XCTAssertFalse(store.addCustomShortcut(name: "   ", url: "https://jwb.szu.edu.cn/"))
        XCTAssertFalse(store.addCustomShortcut(name: "教务部", url: "javascript:alert(1)"))
        XCTAssertEqual(changeCount, 0)

        XCTAssertTrue(store.addCustomShortcut(name: "教务部", url: "https://jwb.szu.edu.cn/"))
        XCTAssertEqual(changeCount, 1)
        let added = try XCTUnwrap(store.shortcuts.first { $0.name == "教务部" })
        XCTAssertFalse(added.isBuiltIn)

        let wasHRFavorite = try XCTUnwrap(store.shortcuts.first { $0.id == "szu-hr" }).isFavorite
        store.toggleFavoriteShortcut("szu-hr")
        XCTAssertEqual(changeCount, 2)
        XCTAssertEqual(store.shortcuts.first { $0.id == "szu-hr" }?.isFavorite, !wasHRFavorite)

        store.toggleMenuBarPin("szu-pkulaw")
        XCTAssertEqual(changeCount, 3)
        XCTAssertTrue(store.isPinnedToMenuBar("szu-pkulaw"))
        XCTAssertEqual(store.menuBarPinnedShortcuts.count, MenuBarPinStore.slotCount)

        store.removeCustomShortcut(added.id)
        XCTAssertEqual(changeCount, 4)
        XCTAssertNil(store.shortcuts.first { $0.id == added.id })

        let reloaded = ShortcutCatalogStore(shortcutsURL: shortcutsURL, menuBarPinsURL: pinsURL)
        XCTAssertNil(reloaded.shortcuts.first { $0.id == added.id })
        XCTAssertEqual(reloaded.shortcuts.first { $0.id == "szu-hr" }?.isFavorite, !wasHRFavorite)
        XCTAssertTrue(reloaded.isPinnedToMenuBar("szu-pkulaw"))
    }

    func testWorkbenchChromeStoreUpdateCheckIsolation() {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let catalog = ShortcutCatalogStore(
            shortcutsURL: tempDir.appendingPathComponent("shortcuts.json"),
            menuBarPinsURL: tempDir.appendingPathComponent("menubar-pins.json")
        )
        let chrome = WorkbenchChromeStore()
        let session = SessionModel(
            catalog: catalog,
            chrome: chrome,
            shortcutsFallbackURL: tempDir.appendingPathComponent("shortcuts.json")
        )

        var chromeChanges = 0
        var catalogChanges = 0
        var sessionChanges = 0
        let c1 = chrome.objectWillChange.sink { _ in chromeChanges += 1 }
        let c2 = catalog.objectWillChange.sink { _ in catalogChanges += 1 }
        let c3 = session.objectWillChange.sink { _ in sessionChanges += 1 }
        defer { c1.cancel(); c2.cancel(); c3.cancel() }

        chrome.checkForUpdates()
        XCTAssertEqual(chrome.updateCheckFeedback, chrome.aboutMetadata.updateStatusText)

        chrome.isEnglishLocale = true
        chrome.checkForUpdates()
        XCTAssertEqual(
            chrome.updateCheckFeedback,
            "Up to date (v\(chrome.aboutMetadata.version), Sparkle EdDSA verified)"
        )
        XCTAssertEqual(chromeChanges, 3)
        XCTAssertEqual(catalogChanges, 0)
        XCTAssertEqual(sessionChanges, 0)
    }

    func testSessionModelHeadlessInitInternalStateSilenceAndConnectionStateDeduplication() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let missingFallback = tempDir.appendingPathComponent("missing-shortcuts.json")

        let session = SessionModel(catalog: nil, chrome: nil, shortcutsFallbackURL: missingFallback)
        XCTAssertNil(session.catalog)
        XCTAssertNil(session.chrome)
        XCTAssertFalse(FileManager.default.fileExists(atPath: tempDir.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: missingFallback.path))

        var sessionChanges = 0
        var iconChanges = 0
        let sessionSub = session.objectWillChange.sink { _ in sessionChanges += 1 }
        let iconSub = session.connectionState.objectWillChange.sink { _ in iconChanges += 1 }
        defer { sessionSub.cancel(); iconSub.cancel() }

        session.setConnectionPhase("discovering")
        session.setConnectionPhase("backend-authenticating")
        var updatedPolicy = PolicyObservation()
        updatedPolicy.receive(Message(command: 20, payload: Data(#"{"content":{"checkStatus":2,"healthStatus":0}}"#.utf8)))
        session.policy = updatedPolicy
        XCTAssertEqual(session.policy.endpointCheck, .healthy)
        session.workbenchResources = [
            BackendUrlResource(id: "r1", name: "内部网", url: "https://www1.szu.edu.cn/")
        ]
        session.pendingShortcutAfterConnect = CampusShortcuts.defaultShortcuts.first
        XCTAssertEqual(sessionChanges, 0)
        XCTAssertEqual(iconChanges, 0)

        session.status = .unknown
        session.status = .connecting
        session.detail = "正在建立零信任网络隧道..."
        session.status = .disconnected
        XCTAssertEqual(iconChanges, 0)
        XCTAssertFalse(session.isConnected)

        session.status = .connecting
        XCTAssertEqual(iconChanges, 0)

        session.status = .connected
        XCTAssertEqual(iconChanges, 1)
        XCTAssertTrue(session.isConnected)

        session.status = .connected
        XCTAssertEqual(iconChanges, 1)

        session.status = .disconnecting
        XCTAssertEqual(iconChanges, 2)
        XCTAssertFalse(session.isConnected)
    }
}
