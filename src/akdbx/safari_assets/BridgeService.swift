// Per-application XPC helper. It forwards sealed frames to the same-user
// broker; it never reads a vault, a TLS key or a plaintext secret.
import Foundation
import Darwin

private final class BrokerService: NSObject, LocalBrokerBridge {
    private let manager: BridgeSessions?
    override init() {
        manager = (try? BrokerConnection.defaultPath()).map(BridgeSessions.init)
        super.init()
    }
    func close() { manager?.close() }

    func request(_ data: Data, reply: @escaping (Data) -> Void) {
        DispatchQueue.global(qos: .userInitiated).async {
            var response: [String: Any] = ["ok": false, "error": "local broker unavailable"]
            if data.count <= 66048,
               let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               Set(object.keys) == ["message", "profile"],
               let message = object["message"] as? [String: Any],
               let profile = object["profile"] as? String, profile.utf8.count <= 128,
               let manager = self.manager {
                response = manager.handle(message, profile: profile)
            }
            let result = try? JSONSerialization.data(withJSONObject: response)
            if let result, result.count <= 66048 { reply(result) }
            else { reply(Data("{\"ok\":false}".utf8)) }
        }
    }
}

private final class BrokerListener: NSObject, NSXPCListenerDelegate {
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        // launchd scopes this embedded service to its owning application. The
        // caller UID is independently checked before exposing the protocol.
        guard connection.effectiveUserIdentifier == getuid() else { return false }
        let service = BrokerService()
        connection.exportedInterface = NSXPCInterface(with: LocalBrokerBridge.self)
        connection.exportedObject = service
        connection.invalidationHandler = { [weak service] in service?.close() }
        connection.resume()
        return true
    }
}

@main struct BrokerServiceMain {
    static func main() {
        let delegate = BrokerListener()
        let listener = NSXPCListener.service()
        listener.delegate = delegate
        listener.resume()
        RunLoop.current.run()
    }
}
