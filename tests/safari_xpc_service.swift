// Disposable native IPC proof; not included in the shipped app.
import Foundation
import Darwin

final class ProbeService: NSObject, NativeBridgeProbe {
    private let manager = BridgeSessions(socketPath: try! BrokerConnection.defaultPath())

    func request(_ data: Data, reply: @escaping (Data) -> Void) {
        DispatchQueue.global(qos: .userInitiated).async {
            guard data.count <= 66048,
                  let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let message = object["message"] as? [String: Any],
                  let profile = object["profile"] as? String else {
                reply(Data("{\"ok\":false}".utf8))
                return
            }
            let response = self.manager.handle(message, profile: profile)
            reply((try? JSONSerialization.data(withJSONObject: response)) ?? Data("{\"ok\":false}".utf8))
        }
    }
}

final class ProbeListener: NSObject, NSXPCListenerDelegate {
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        guard connection.effectiveUserIdentifier == getuid() else { return false }
        connection.exportedInterface = NSXPCInterface(with: NativeBridgeProbe.self)
        connection.exportedObject = ProbeService()
        connection.resume()
        return true
    }
}

@main struct ServiceMain {
    static func main() {
        let delegate = ProbeListener()
        let listener = NSXPCListener.service()
        listener.delegate = delegate
        listener.resume()
        RunLoop.current.run()
    }
}
