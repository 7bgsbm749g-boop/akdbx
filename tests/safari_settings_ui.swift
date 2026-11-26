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

    func enable(_ checkbox: XCUIElement) {
        XCTAssertTrue(checkbox.waitForExistence(timeout: 5), "Missing Safari checkbox")
        if (checkbox.value as? String) != "1" { checkbox.click() }
    }

    func testPackagedExtensionAttachesToBroker() throws {
        continueAfterFailure = false
        defer { record("safari-ui-final") }
        safari.launch()
        record("safari-ui-launched")
        let start = safari.buttons["Start Using Safari"]
        if start.waitForExistence(timeout: 3) { start.click() }
        safari.typeKey(",", modifierFlags: .command)
        record("safari-ui-settings")
        tab("Advanced")
        record("safari-ui-advanced")
        var developer = safari.checkBoxes.matching(NSPredicate(
            format: "label CONTAINS[c] %@", "web developers")).firstMatch
        if !developer.exists {
            developer = safari.checkBoxes.matching(NSPredicate(
                format: "label CONTAINS[c] %@", "Develop menu")).firstMatch
        }
        enable(developer)
        tab("Developer")
        record("safari-ui-developer")
        let unsigned = safari.checkBoxes.matching(NSPredicate(
            format: "label CONTAINS[c] %@", "Allow unsigned extensions")).firstMatch
        enable(unsigned)
        record("safari-ui-after-unsigned")
        XCTAssertEqual(unsigned.value as? String, "1", "Safari did not permit unsigned developer extensions")
        tab("Extensions")
        record("safari-ui-extensions")
        let extensionToggle = safari.checkBoxes.matching(NSPredicate(
            format: "label CONTAINS[c] %@", "akdbx")).firstMatch
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
