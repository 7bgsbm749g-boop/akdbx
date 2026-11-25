import Foundation
import SafariServices

final class SafariWebExtensionHandler: NSObject, NSExtensionRequestHandling {
    private static let bridge = BrokerBridgeClient()

    func beginRequest(with context: NSExtensionContext) {
        guard let item = context.inputItems.first as? NSExtensionItem,
              let info = item.userInfo,
              let request = info[SFExtensionMessageKey] as? [String: Any] else {
            context.completeRequest(returningItems: nil)
            return
        }
        // Safari supplies the profile; JavaScript cannot choose another one.
        let profile = (info[SFExtensionProfileKey] as? UUID)?.uuidString ?? "normal"
        Self.bridge.request(request, profile: profile) { value in
            let reply = NSExtensionItem()
            reply.userInfo = [SFExtensionMessageKey: value]
            context.completeRequest(returningItems: [reply])
        }
    }
}
