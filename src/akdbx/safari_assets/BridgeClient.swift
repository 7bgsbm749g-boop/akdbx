import Foundation

private let bridgeService = "org.akdbx.safari.Extension.Bridge"
private let transportLimit = 66048
private let bridgeUnavailable: [String: Any] = ["ok": false, "error": "local broker unavailable"]

private final class BridgeReply {
    private let lock = NSLock()
    private var completed = false
    private let reply: ([String: Any]) -> Void
    init(_ reply: @escaping ([String: Any]) -> Void) { self.reply = reply }
    @discardableResult func finish(_ value: [String: Any]) -> Bool {
        lock.lock()
        guard !completed else { lock.unlock(); return false }
        completed = true
        lock.unlock()
        reply(value)
        return true
    }
}

final class BrokerBridgeClient {
    private let lock = NSLock()
    private var connection: NSXPCConnection?

    private func connected() -> NSXPCConnection {
        lock.lock()
        defer { lock.unlock() }
        if let connection { return connection }
        let next = NSXPCConnection(serviceName: bridgeService)
        next.remoteObjectInterface = NSXPCInterface(with: LocalBrokerBridge.self)
        next.invalidationHandler = { [weak self, weak next] in
            guard let self else { return }
            self.lock.lock()
            if self.connection === next { self.connection = nil }
            self.lock.unlock()
        }
        next.interruptionHandler = { [weak next] in next?.invalidate() }
        connection = next
        next.resume()
        return next
    }

    func request(_ message: [String: Any], profile: String, reply: @escaping ([String: Any]) -> Void) {
        guard profile.utf8.count <= 128,
              let data = try? JSONSerialization.data(withJSONObject: ["message": message, "profile": profile]),
              data.count <= transportLimit else { reply(bridgeUnavailable); return }
        let connection = connected()
        let completion = BridgeReply(reply)
        let remote = connection.remoteObjectProxyWithErrorHandler { _ in
            completion.finish(bridgeUnavailable)
            connection.invalidate()
        }
        guard let proxy = remote as? LocalBrokerBridge else {
            completion.finish(bridgeUnavailable)
            connection.invalidate()
            return
        }
        proxy.request(data) { result in
            guard result.count <= transportLimit,
                  let value = try? JSONSerialization.jsonObject(with: result) as? [String: Any] else {
                completion.finish(bridgeUnavailable)
                connection.invalidate()
                return
            }
            completion.finish(value)
        }
        DispatchQueue.global().asyncAfter(deadline: .now() + 10) {
            if completion.finish(bridgeUnavailable) { connection.invalidate() }
        }
    }

    deinit { connection?.invalidate() }
}
