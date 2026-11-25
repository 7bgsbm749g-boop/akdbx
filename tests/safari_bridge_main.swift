// Synthetic native test harness; not included in the shipped app.
import Foundation
import Darwin

@main
struct BridgeMain {
    static func main() throws {
        if CommandLine.arguments.count == 3 && CommandLine.arguments[1] == "--probe-denied" {
            do {
                _ = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[2]))
                print("sandbox probe unexpectedly readable")
                exit(1)
            } catch {
                print("denied")
                return
            }
        }
        let manager = BridgeSessions(socketPath: try BrokerConnection.defaultPath())
        while let line = readLine() {
            guard line.utf8.count <= 66048,
                  let object = try JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any],
                  let message = object["message"] as? [String: Any],
                  let profile = object["profile"] as? String else { exit(2) }
            let result: [String: Any]
            if message["op"] as? String == "test-fd-count" {
                let count = (0..<1024).filter { fcntl(Int32($0), F_GETFD) >= 0 }.count
                result = ["ok": true, "count": count]
            } else {
                result = manager.handle(message, profile: profile)
            }
            let data = try JSONSerialization.data(withJSONObject: result, options: [.sortedKeys]) + Data([10])
            try FileHandle.standardOutput.write(contentsOf: data)
        }
    }
}
