import Foundation

struct CASIdentityPolicy: Decodable {
    let rejectedByNonCredit: Bool?
    let userInfoCompletion: Bool?
    let creditFlag: Int?
    let username: String?
    let authConfigId: Int?
    enum CodingKeys: String, CodingKey { case rejectedByNonCredit, userInfoCompletion, creditFlag, username, authConfigId }
    // Official CAS consumes these flags by truthiness. Live szu replies
    // use a numeric userInfoCompletion; nonzero must never bypass it.
    private static func flag(_ values: KeyedDecodingContainer<CodingKeys>, _ key: CodingKeys) throws -> Bool? {
        guard values.contains(key) else { return nil }
        if let boolean = try? values.decode(Bool.self, forKey: key) { return boolean }
        return try values.decode(Int.self, forKey: key) != 0
    }
    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        rejectedByNonCredit = try Self.flag(values, .rejectedByNonCredit)
        userInfoCompletion = try Self.flag(values, .userInfoCompletion)
        creditFlag = try values.decodeIfPresent(Int.self, forKey: .creditFlag)
        username = try values.decodeIfPresent(String.self, forKey: .username)
        if try !values.contains(.authConfigId) || values.decodeNil(forKey: .authConfigId) { authConfigId = nil }
        else {
            let number: Int
            if let raw = try? values.decode(String.self, forKey: .authConfigId), !raw.isEmpty,
               raw.utf8.allSatisfy({ (48...57).contains($0) }), let parsed = Int(raw) { number = parsed }
            else { number = try values.decode(Int.self, forKey: .authConfigId) }
            guard number >= 0 else { throw NativeSettingsError.invalidValue }
            authConfigId = number == 0 ? nil : number
        }
    }

    var decision: (CASPreAuthentication.State, AuthenticatedIdentity?) {
        if rejectedByNonCredit == true { return (.deviceRejected, nil) }
        if userInfoCompletion == true { return (.informationRequired, nil) }
        guard let creditFlag, (0...2).contains(creditFlag) else { return (.unsupportedResponse, nil) }
        var identity: AuthenticatedIdentity?
        if let username, !username.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
           username.rangeOfCharacter(from: .controlCharacters) == nil {
            identity = AuthenticatedIdentity(username: username, authConfigId: authConfigId)
        }
        return (.responseValidated(creditFlag: creditFlag), identity)
    }
}
