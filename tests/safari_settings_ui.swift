import XCTest
import Foundation

// This source runs only on the explicitly selected, disposable CI Mac. It
// enables the packaged app through visible Safari controls, not private prefs.
@MainActor
final class SafariSettingsTests: XCTestCase {
    let safari = XCUIApplication(bundleIdentifier: "com.apple.Safari")
    let artifactDirectory = URL(fileURLWithPath: __ARTIFACT_DIR__)

    func record(_ stage: String) {
        print("Safari UI stage: \(stage)\n\(safari.debugDescription.prefix(60000))")
        let image = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        image.name = stage
        image.lifetime = .keepAlways
        add(image)
        let tree = XCTAttachment(string: String(safari.debugDescription.prefix(60000)))
        tree.name = stage + "-tree"
        tree.lifetime = .keepAlways
        add(tree)
        try? String(safari.debugDescription.prefix(60000)).write(to: artifactDirectory.appendingPathComponent(stage + ".txt"),
                                          atomically: true, encoding: .utf8)
        try? XCUIScreen.main.screenshot().pngRepresentation.write(
            to: artifactDirectory.appendingPathComponent(stage + ".png"))
    }

    func tab(_ name: String) {
        let predicate = NSPredicate(format: "label == %@ OR title == %@", name, name)
        let button = safari.buttons.matching(predicate).firstMatch
        if button.waitForExistence(timeout: 3) { button.click(); return }
        let radio = safari.radioButtons.matching(predicate).firstMatch
        XCTAssertTrue(radio.waitForExistence(timeout: 3), "Missing Safari settings tab: \(name)")
        radio.click()
    }

    func checkbox(containing name: String) -> XCUIElement {
        // AppKit controls can expose their visible name as title rather than
        // label. Both Safari versions in the native matrix use title here.
        safari.checkBoxes.matching(NSPredicate(
            format: "label CONTAINS[c] %@ OR title CONTAINS[c] %@", name, name)).firstMatch
    }

    func enable(_ checkbox: XCUIElement) {
        XCTAssertTrue(checkbox.waitForExistence(timeout: 5), "Missing Safari checkbox")
        if String(describing: checkbox.value ?? "") != "1" { checkbox.click() }
    }

    func testPackagedExtensionAttachesToBroker() throws {
        continueAfterFailure = false
        addUIInterruptionMonitor(withDescription: "Disposable Python observer local network") { alert in
            let description = alert.debugDescription
            guard description.contains("Python"), description.contains("local networks") else { return false }
            let allow = alert.buttons["Allow"]
            guard allow.exists else { return false }
            allow.click()
            return true
        }
        defer { record("safari-ui-final") }
        safari.launch()
        record("safari-ui-launched")
        let start = safari.buttons["Start Using Safari"]
        if start.waitForExistence(timeout: 3) { start.click() }
        safari.typeKey(",", modifierFlags: .command)
        record("safari-ui-settings")
        tab("Advanced")
        record("safari-ui-advanced")
        var developer = checkbox(containing: "web developers")
        if !developer.exists {
            developer = checkbox(containing: "Develop menu")
        }
        enable(developer)
        tab("Developer")
        record("safari-ui-developer")
        let unsigned = checkbox(containing: "Allow unsigned extensions")
        enable(unsigned)
        record("safari-ui-after-unsigned")
        let passwordField = safari.sheets.secureTextFields["Password"]
        if passwordField.waitForExistence(timeout: 3) {
            // The Python fixture created this credential on this disposable
            // VM. No real user password or keychain is read by the test.
            guard let password = ProcessInfo.processInfo.environment["AKDBX_CI_TEST_PASSWORD"] else {
                XCTFail("Missing disposable CI account authorization")
                return
            }
            passwordField.click()
            passwordField.typeText(password)
            safari.sheets.buttons["OK"].click()
            XCTAssertTrue(passwordField.waitForNonExistence(timeout: 5), "Safari authorization did not complete")
        }
        record("safari-ui-authorized")
        XCTAssertEqual(String(describing: unsigned.value ?? ""), "1",
                       "Safari did not permit unsigned developer extensions")
        tab("Extensions")
        record("safari-ui-extensions")
        let extensionToggle = checkbox(containing: "akdbx")
        enable(extensionToggle)
        let turnOn = safari.buttons["Turn On"]
        if turnOn.waitForExistence(timeout: 2) { turnOn.click() }
        record("safari-ui-enabled")
        let probe = URL(string: __PROBE_URL__)!
        let deadline = Date().addingTimeInterval(20)
        while Date() < deadline {
            // The Python observer reports only a real, authenticated broker
            // channel. This does not create a native connection or bypass it.
            if (try? String(contentsOf: probe, encoding: .utf8)) == "attached" { return }
            Thread.sleep(forTimeInterval: 0.25)
        }
        XCTFail("Safari's installed native extension did not attach to its local broker")
    }
}
