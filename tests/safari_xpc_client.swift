// Disposable native IPC proof; not included in the shipped app.
import Foundation
import Darwin

@main struct ClientMain {
    static func main() throws {
        if CommandLine.arguments.count == 3 && CommandLine.arguments[1] == "--probe-denied" {
            do {
                _ = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[2]))
                exit(1)
            } catch { print("denied"); return }
        }
        let client = BrokerBridgeClient()
        while let line = readLine() {
            guard line.utf8.count <= 66048,
                  let object = try JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any],
                  let message = object["message"] as? [String: Any],
                  let profile = object["profile"] as? String else { exit(2) }
            let completed = DispatchSemaphore(value: 0)
            client.request(message, profile: profile) { result in
                let data = try! JSONSerialization.data(withJSONObject: result)
                print(String(data: data, encoding: .utf8)!)
                fflush(stdout)
                completed.signal()
            }
            guard completed.wait(timeout: .now() + 12) == .success else { exit(3) }
        }
    }
}
