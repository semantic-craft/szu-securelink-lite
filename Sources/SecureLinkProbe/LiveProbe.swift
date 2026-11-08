import Foundation
import SecureLinkTransport

func runLiveProbe(publicKeyDER: Data, port: UInt16) throws -> LiveReport {
    try runNativeSession(publicKeyDER: publicKeyDER, port: port, onStatus: { status in
        // Only a finite state enum is observable; message bodies remain in memory.
        FileHandle.standardError.write(Data(("tunnel=" + status.rawValue + "\n").utf8))
    })
}
