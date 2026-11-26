import AppKit
import ApplicationServices

if CommandLine.arguments.last == "app" {
    let app = NSApplication.shared
    app.setActivationPolicy(.regular)
    let window = NSWindow(contentRect: NSMakeRect(200, 200, 360, 160),
                          styleMask: [.titled, .closable], backing: .buffered, defer: false)
    let field = NSSecureTextField(frame: NSMakeRect(20, 40, 300, 30))
    window.contentView!.addSubview(field)
    window.makeKeyAndOrderFront(nil)
    app.activate(ignoringOtherApps: true)
    window.makeFirstResponder(field)
    withExtendedLifetime((window, field)) { app.run() }
} else {
    guard AXIsProcessTrusted() else {
        print("Accessibility permission unavailable to the runner")
        exit(2)
    }
    let app = AXUIElementCreateApplication(Int32(CommandLine.arguments[1])!)
    func get(_ node: AXUIElement, _ name: String) -> (AXError, CFTypeRef?) {
        var value: CFTypeRef?
        let result = AXUIElementCopyAttributeValue(node, name as CFString, &value)
        return (result, value)
    }
    let deadline = Date().addingTimeInterval(15)
    repeat {
        if let obj = get(app, "AXFocusedUIElement").1 {
            let field = obj as! AXUIElement
            if get(field, "AXSubrole").1 as? String == "AXSecureTextField" {
                var settable = DarwinBoolean(false)
                let ability = AXUIElementIsAttributeSettable(field, "AXValue" as CFString, &settable)
                let countBefore = get(field, "AXNumberOfCharacters").0
                let write = AXUIElementSetAttributeValue(field, "AXValue" as CFString, "fixture" as CFString)
                let (countAfter, value) = get(field, "AXNumberOfCharacters")
                print("Stock NSSecureTextField: settable query=\(ability.rawValue) settable=\(settable.boolValue) count-before=\(countBefore.rawValue) write=\(write.rawValue) count-after=\(countAfter.rawValue) length-matched=\((value as? Int) == 7)")
                exit(write == .success && countAfter == .success && (value as? Int) == 7 ? 0 : 3)
            }
        }
        Thread.sleep(forTimeInterval: 0.1)
    } while Date() < deadline
    print("No focused stock secure field appeared")
    exit(4)
}
