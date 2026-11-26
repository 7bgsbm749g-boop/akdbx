import AppKit
import ApplicationServices

if CommandLine.arguments[1] == "app" {
    let app = NSApplication.shared
    app.setActivationPolicy(.regular)
    let window = NSWindow(contentRect: NSMakeRect(200, 200, 360, 160),
                          styleMask: [.titled, .closable], backing: .buffered, defer: false)
    let rect = NSMakeRect(20, 40, 300, 30)
    let field: NSView
    switch CommandLine.arguments[2] {
    case "plain": field = NSTextField(frame: rect)
    case "read", "text":
        let view = NSTextView(frame: rect)
        view.isEditable = CommandLine.arguments[2] == "text"
        view.isSelectable = true
        view.string = "fixture"
        field = view
    default: field = NSSecureTextField(frame: rect)
    }
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
            if ["AXTextField", "AXTextArea"].contains(get(field, "AXRole").1 as? String ?? "") {
                print("role", get(field, "AXRole").1 as? String ?? "?", "subrole", get(field, "AXSubrole").1 as? String ?? "none", "enabled", get(field, "AXEnabled").1 as? Bool as Any, "editable", get(field, "AXEditable").1 as? Bool as Any)
                for name in ["AXSelectedText", "AXVisibleCharacterRange", "AXValue", "AXFocused", "AXProtectedContent"] {
                    var available = DarwinBoolean(false)
                    let e = AXUIElementIsAttributeSettable(field, name as CFString, &available)
                    print(name, e.rawValue, available.boolValue)
                }
                var settable = DarwinBoolean(false)
                let ability = AXUIElementIsAttributeSettable(field, "AXValue" as CFString, &settable)
                let countBefore = get(field, "AXNumberOfCharacters").0
                let write = AXUIElementSetAttributeValue(field, "AXValue" as CFString, "fixture" as CFString)
                let (countAfter, value) = get(field, "AXNumberOfCharacters")
                print("Text control: settable query=\(ability.rawValue) settable=\(settable.boolValue) count-before=\(countBefore.rawValue) write=\(write.rawValue) count-after=\(countAfter.rawValue) length-matched=\((value as? Int) == 7)")
                exit(0)
            }
        }
        Thread.sleep(forTimeInterval: 0.1)
    } while Date() < deadline
    print("No focused stock secure field appeared")
    exit(4)
}
