import Foundation
import SafariServices

final class SafariWebExtensionHandler: NSObject, NSExtensionRequestHandling {
    private static let bridge: BridgeSessions? = (try? BrokerConnection.defaultPath()).map(BridgeSessions.init)

    func beginRequest(with context: NSExtensionContext) {
        guard let item = context.inputItems.first as? NSExtensionItem,
              let info = item.userInfo,
              let request = info[SFExtensionMessageKey] as? [String: Any] else {
            context.completeRequest(returningItems: nil)
            return
        }
        // Safari supplies the profile; JavaScript cannot choose another one.
        let profile = (info[SFExtensionProfileKey] as? UUID)?.uuidString ?? "normal"
        DispatchQueue.global(qos: .userInitiated).async {
            let value = Self.bridge?.handle(request, profile: profile)
                ?? ["ok": false, "error": "local broker unavailable"]
            let reply = NSExtensionItem()
            reply.userInfo = [SFExtensionMessageKey: value]
            context.completeRequest(returningItems: [reply])
        }
    }
}
