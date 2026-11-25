// Synthetic native test harness; not included in the shipped app.
import Foundation
import Darwin

struct NativeProbeFailure: Error, CustomStringConvertible {
    let line: Int
    let code: Int32
    var description: String { "line=\(line), errno=\(code)" }
}

private func runtimeProbe() throws -> [[String: Any]] {
    var path = ""
    var result: [[String: Any]] = []
    for part in try BrokerConnection.defaultPath().split(separator: "/").dropLast() {
        path += "/" + String(part)
        errno = 0
        let fd = Darwin.open(path, O_EVTONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        let openError = fd >= 0 ? 0 : errno
        if fd >= 0 { Darwin.close(fd) }
        var info = stat()
        errno = 0
        let metadata = lstat(path, &info)
        let statError = metadata == 0 ? 0 : errno
        errno = 0
        let acl = acl_get_link_np(path, ACL_TYPE_EXTENDED)
        let aclError = acl == nil ? errno : 0
        if let acl { acl_free(UnsafeMutableRawPointer(acl)) }
        result.append(["component": String(part), "open_errno": openError,
                       "stat_errno": statError, "acl_errno": aclError])
    }
    return result
}

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
            } else if message["op"] as? String == "test-runtime-probe" {
                result = ["ok": true, "components": try runtimeProbe()]
            } else {
                result = manager.handle(message, profile: profile)
            }
            let data = try JSONSerialization.data(withJSONObject: result, options: [.sortedKeys]) + Data([10])
            try FileHandle.standardOutput.write(contentsOf: data)
        }
    }
}
