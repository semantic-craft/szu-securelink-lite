import Foundation

/// No authentication tokens enter this reducer. Initialization is not tunnel or health success.
public final class PolicyInitialization {
    public enum State: Equatable, Sendable {
        case idle, awaitingDevice, awaitingLoad, awaitingConfiguration, initialized
        case serviceRejected, unsupportedResponse, timedOut, cancelled
    }
    public private(set) var state: State = .idle
    public private(set) var vpnConfiguration: VPNConfiguration?
    public private(set) var securityCheckSent = false
    public private(set) var observation = PolicyObservation()
    private let identity: AuthenticatedIdentity
    private let settings: NativeSettings
    private var requestID: String?
    private var startedAt: Duration?
    private var configurationReceived = false

    public init(identity: AuthenticatedIdentity, settings: NativeSettings) {
        self.identity = identity; self.settings = settings
    }
    public func begin(elapsed: Duration) -> Message? {
        guard state == .idle else { return nil }
        state = .awaitingDevice; startedAt = elapsed
        return Message(command: 16, payload: Data("{}".utf8))
    }
    public func advance(elapsed: Duration) {
        guard let startedAt else { return }
        if elapsed < startedAt || elapsed - startedAt >= .seconds(90) { stop(.timedOut) }
    }
    public func cancel() { stop(.cancelled) }
    public func didSend(command: UInt32, elapsed: Duration) {
        advance(elapsed: elapsed)
        guard state == .awaitingConfiguration, command == 20 else { return }
        securityCheckSent = true
        finishIfReady()
    }
    public func receive(_ message: Message, elapsed: Duration) throws -> [Message] {
        advance(elapsed: elapsed)
        guard [.awaitingDevice, .awaitingLoad, .awaitingConfiguration, .initialized].contains(state) else { return [] }
        if message.command == 20 || message.command == 21 {
            if message.command == 21 || securityCheckSent { observation.receive(message) }
            return []
        }
        if state == .awaitingDevice, message.command == 16 {
            guard let object = try? JSONSerialization.jsonObject(with: message.payload) as? [String: Any],
                  object["content"] == nil, object["returnCode"] == nil,
                  object["error"] == nil, object["errorCode"] == nil,
                  let device = try? JSONDecoder().decode(Device.self, from: message.payload),
                  !Set(object.keys).isDisjoint(with: Device.fields) else { stop(.unsupportedResponse); return [] }
            guard object.contains(where: { Device.fields.contains($0.key) && !($0.value is NSNull) }) else {
                stop(.unsupportedResponse); return []
            }
            var body: [String: Any] = ["system": "3"]
            if let value = device.intranetIp { body["intranetIp"] = value }
            if let value = device.dns { body["dns"] = value }
            if let value = device.wifiSsid { body["wifiSsid"] = value }
            state = .awaitingLoad; startedAt = elapsed
            return [try api("loadAction", body: body)]
        }
        guard message.command == 28, state == .awaitingLoad || state == .awaitingConfiguration else { return [] }
        // Read only the correlation first: unrelated replies cannot poison this attempt.
        guard let object = try? JSONSerialization.jsonObject(with: message.payload) as? [String: Any],
              let id = object["id"] as? String, id == requestID else { return [] }
        guard let reply = try? JSONDecoder().decode(APIReply.self, from: message.payload) else { stop(.unsupportedResponse); return [] }
        guard reply.returnCode == nil || reply.returnCode == 1 else { stop(.serviceRejected); return [] }
        guard let content = object["content"] as? [String: Any] else { stop(.unsupportedResponse); return [] }
        if state == .awaitingLoad {
            // Load data is deliberately not used as a source of authenticated identity.
            state = .awaitingConfiguration; startedAt = elapsed
            return [try api("extraConfig", body: ["system": "3"]),
                    try settings.message(identity: identity, autoReconnect: false),
                    try messageJSON(20, ["org": "szu", "username": identity.username, "system": 3, "version": "3.11.1", "triggerBy": 0]),
                    try messageJSON(73, ["authType": 11])]
        }
        if let value = content["vpnConfig"] {
            guard !(value is NSNull), JSONSerialization.isValidJSONObject(value),
                  let data = try? JSONSerialization.data(withJSONObject: value),
                  let config = try? JSONDecoder().decode(VPNConfiguration.self, from: data), config.isValid else {
                stop(.unsupportedResponse); return []
            }
            vpnConfiguration = config
        }
        requestID = nil
        configurationReceived = true
        finishIfReady()
        return []
    }
    private func finishIfReady() {
        if configurationReceived && securityCheckSent { stop(.initialized) }
    }
    private func stop(_ next: State) { state = next; startedAt = nil; requestID = nil }
    private func api(_ action: String, body: [String: Any]) throws -> Message {
        let id = UUID().uuidString; requestID = id
        return try messageJSON(28, ["id": id, "path": "/networkApi/is/network/\(action)?locale=zh_CN",
                                    "header": ["apiVersion": "5.18.0.0"], "body": body, "tokenType": 2, "method": "POST"])
    }
    private func messageJSON(_ command: UInt32, _ fields: [String: Any]) throws -> Message {
        Message(command: command, payload: try JSONSerialization.data(withJSONObject: fields))
    }
    private struct APIReply: Decodable {
        let returnCode: Int?
        enum CodingKeys: String, CodingKey { case returnCode }
        init(from decoder: Decoder) throws {
            let values = try decoder.container(keyedBy: CodingKeys.self)
            returnCode = values.contains(.returnCode) ? try values.decode(Int.self, forKey: .returnCode) : nil
        }
    }
    private struct Device: Codable {
        static let fields: Set<String> = ["deviceId", "systemName", "deviceName", "deviceMac", "deviceWiredMac", "deviceWirelessMac", "deviceModel", "systemModel", "systemBits", "intranetIp", "dns", "wifiSsid"]
        let intranetIp: String?; let dns: String?; let wifiSsid: [String]?
    }
}

/// Minutes from the service remain explicit. Missing/unknown policy never means unlimited online time.
public struct VPNConfiguration: Decodable, Equatable, Sendable {
    public let idleDisconnectEnable: Int?
    public let idleDisconnectTime: Double?
    public let forceDisconnectEnable: Int?
    public let forceDisconnectTime: Double?
    public let promptMinutes: Double?
    public let renewalMethod: Int?
    public var idleDisconnectSeconds: Double? { idleDisconnectTime.map { $0 * 60 } }
    public var forceDisconnectSeconds: Double? { forceDisconnectTime.map { $0 * 60 } }
    public var promptSeconds: Double? { promptMinutes.map { $0 * 60 } }
    public var isVerified: Bool {
        guard let idleDisconnectEnable, let forceDisconnectEnable, renewalMethod == 0 else { return false }
        return (idleDisconnectEnable == 0 || idleDisconnectTime != nil) && (forceDisconnectEnable == 0 || forceDisconnectTime != nil)
    }
    var isValid: Bool {
        [idleDisconnectEnable, forceDisconnectEnable].allSatisfy { $0 == nil || $0 == 0 || $0 == 1 } &&
        [idleDisconnectTime, forceDisconnectTime, promptMinutes].allSatisfy { $0 == nil || ($0!.isFinite && $0! >= 0 && $0! <= Double(Int.max) / 60) }
    }
}
