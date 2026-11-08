import XCTest
@testable import SecureLinkCore

final class AuthenticationReplyShapeTests: XCTestCase {
    func testEndpointEvidenceDoesNotExportItemsOrArbitraryNumbers() {
        let data = Data(#"{"content":{"enable":0,"checkStatus":1,"healthStatus":null,"checkItems":[{"private":"secret"}],"username":"private-user"}}"#.utf8)
        let shape = EndpointReplyShape.describe(data)
        XCTAssertEqual(shape["enableEnum"], "0")
        XCTAssertEqual(shape["checkStatusEnum"], "1")
        XCTAssertEqual(shape["healthStatus"], "null")
        XCTAssertEqual(shape["checkItems"], "array")
        XCTAssertNil(shape["username"])
        XCTAssertFalse(shape.description.contains("secret"))
        XCTAssertEqual(EndpointReplyShape.describe(Data(#"{"healthStatus":99999}"#.utf8))["healthStatusEnum"], "other")
    }
    func testOnlyFixedNamesAndTypesEscape() {
        let data = Data(#"{"returnCode":1,"secret-key":"secret-value","content":{"username":"private-user","authToken":"private-token","creditFlag":true,"authConfigId":null,"userInfoCompletion":0}}"#.utf8)
        let shape = AuthenticationReplyShape.describe(data)
        XCTAssertEqual(shape, ["root":"object", "returnCode":"number", "content":"object", "username":"string", "creditFlag":"boolean", "authConfigId":"null", "userInfoCompletion":"number", "rejectedByNonCredit":"absent"])
        XCTAssertEqual(AuthenticationReplyShape.describe(Data("private-user".utf8)), ["root":"invalid-json"])
        XCTAssertEqual(AuthenticationReplyShape.describe(Data("[]".utf8)), ["root":"array"])
    }
}
