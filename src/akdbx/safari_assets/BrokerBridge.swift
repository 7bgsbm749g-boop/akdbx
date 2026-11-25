// Local macOS broker transport. No vault/key access, decryption or logging.
import Foundation
import CoreFoundation
import Darwin
import Security

enum BridgeError: Error { case refused, unavailable }

private let frameLimit = 64 * 1024 // akdbx.protocol.MAX_MESSAGE
private func now() -> Double { ProcessInfo.processInfo.systemUptime }

private func privateACL(_ fd: Int32) throws {
    errno = 0
    guard let acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED) else {
        if errno == ENOENT { return }
        throw BridgeError.refused
    }
    defer { acl_free(UnsafeMutableRawPointer(acl)) }
    var entry: acl_entry_t?
    for index in 0..<170 {
        errno = 0
        if acl_get_entry(acl, (index == 0 ? ACL_FIRST_ENTRY : ACL_NEXT_ENTRY).rawValue, &entry) != 0 {
            if errno == EINVAL { return }
            throw BridgeError.refused
        }
        var tag = ACL_UNDEFINED_TAG
        guard let entry, acl_get_tag_type(entry, &tag) == 0, tag == ACL_EXTENDED_DENY else {
            throw BridgeError.refused
        }
    }
    throw BridgeError.refused
}

private func checkDirectory(_ fd: Int32, leaf: Bool) throws {
    var info = stat()
    guard fstat(fd, &info) == 0, info.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR) else {
        throw BridgeError.refused
    }
    let uid = getuid()
    if leaf {
        guard info.st_uid == uid, info.st_mode & 0o077 == 0 else { throw BridgeError.refused }
    } else {
        guard info.st_uid == 0 || info.st_uid == uid else { throw BridgeError.refused }
        if info.st_mode & 0o022 != 0 && !(info.st_uid == 0 && info.st_mode & mode_t(S_ISVTX) != 0) {
            throw BridgeError.refused
        }
    }
    try privateACL(fd)
}

private func jsonData(_ value: [String: Any]) throws -> Data {
    let data = try JSONSerialization.data(withJSONObject: value)
    guard !data.isEmpty, data.count <= frameLimit else { throw BridgeError.refused }
    return data
}

final class BrokerConnection {
    private var fd: Int32
    private let closeLock = NSLock()
    private let readLock = NSLock()
    private let writeLock = NSLock()

    static func defaultPath() throws -> String {
        guard let user = getpwuid(getuid()), let home = user.pointee.pw_dir else { throw BridgeError.refused }
        return String(cString: home) + "/Library/Application Support/akdbx/run/s"
    }

    init(path: String) throws {
        fd = -1
        guard path.hasPrefix("/"), !path.utf8.contains(0), path.utf8.count < 104 else { throw BridgeError.refused }
        let parts = path.split(separator: "/").map(String.init)
        guard parts.count >= 2, !parts.contains("."), !parts.contains("..") else { throw BridgeError.refused }
        var held: [Int32] = []
        defer { held.forEach { Darwin.close($0) } }
        // Verify every opened ancestor before connecting to the local broker.
        let flags = O_EVTONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        var directory = Darwin.open("/", flags)
        guard directory >= 0 else { throw BridgeError.refused }
        held.append(directory)
        try checkDirectory(directory, leaf: false)
        for (index, part) in parts.dropLast().enumerated() {
            directory = openat(directory, part, flags)
            guard directory >= 0 else { throw BridgeError.refused }
            held.append(directory)
            try checkDirectory(directory, leaf: index == parts.count - 2)
        }
        var info = stat()
        guard fstatat(directory, parts.last!, &info, AT_SYMLINK_NOFOLLOW) == 0,
              info.st_mode & mode_t(S_IFMT) == mode_t(S_IFSOCK), info.st_uid == getuid(),
              info.st_mode & 0o077 == 0 else { throw BridgeError.refused }
        let socketFD = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard socketFD >= 0 else { throw BridgeError.unavailable }
        var owned = true
        defer { if owned { Darwin.close(socketFD) } }
        guard fcntl(socketFD, F_SETFD, FD_CLOEXEC) == 0,
              fcntl(socketFD, F_SETFL, O_NONBLOCK) == 0 else { throw BridgeError.unavailable }
        var one: Int32 = 1
        guard setsockopt(socketFD, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout.size(ofValue: one))) == 0 else {
            throw BridgeError.unavailable
        }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let bytes = Array(path.utf8) + [0]
        withUnsafeMutableBytes(of: &address.sun_path) { target in target.copyBytes(from: bytes) }
        let result = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(socketFD, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        if result != 0 {
            guard errno == EINPROGRESS || errno == EWOULDBLOCK else { throw BridgeError.unavailable }
            guard try Self.wait(socketFD, events: Int16(POLLOUT), until: now() + 5) else { throw BridgeError.unavailable }
            var error: Int32 = 0
            var size = socklen_t(MemoryLayout.size(ofValue: error))
            guard getsockopt(socketFD, SOL_SOCKET, SO_ERROR, &error, &size) == 0, error == 0 else {
                throw BridgeError.unavailable
            }
        }
        var peerUID: uid_t = 0, peerGID: gid_t = 0
        guard getpeereid(socketFD, &peerUID, &peerGID) == 0, peerUID == getuid() else { throw BridgeError.refused }
        fd = socketFD
        owned = false
    }

    deinit {
        close()
        if fd >= 0 { Darwin.close(fd) }
    }

    func close() {
        closeLock.lock()
        defer { closeLock.unlock() }
        // Shutdown interrupts an in-flight read. The descriptor stays allocated
        // until deinit, so another session cannot reuse it while a call holds us.
        if fd >= 0 { shutdown(fd, SHUT_RDWR) }
    }

    private static func wait(_ fd: Int32, events: Int16, until deadline: Double) throws -> Bool {
        while now() < deadline {
            var descriptor = pollfd(fd: fd, events: events, revents: 0)
            let milliseconds = Int32(max(1, min(5000, (deadline - now()) * 1000)))
            let result = Darwin.poll(&descriptor, 1, milliseconds)
            if result == 0 { return false }
            if result < 0 {
                if errno == EINTR { continue }
                throw BridgeError.unavailable
            }
            guard descriptor.revents & Int16(POLLNVAL | POLLERR) == 0 else { throw BridgeError.unavailable }
            return true // recv/send also detects orderly shutdown and POLLHUP.
        }
        return false
    }

    private func exact(_ size: Int, until deadline: Double) throws -> Data {
        var data = Data(count: size)
        var offset = 0
        while offset < size {
            guard try Self.wait(fd, events: Int16(POLLIN), until: deadline) else { throw BridgeError.unavailable }
            let count = data.withUnsafeMutableBytes { raw in
                Darwin.recv(fd, raw.baseAddress!.advanced(by: offset), size - offset, 0)
            }
            if count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) { continue }
            guard count > 0 else { throw BridgeError.unavailable }
            offset += count
        }
        return data
    }

    func receive() throws -> [String: Any]? {
        guard readLock.try() else { throw BridgeError.refused }
        defer { readLock.unlock() }
        guard try Self.wait(fd, events: Int16(POLLIN), until: now() + 2) else { return nil }
        let deadline = now() + 5
        let header = try exact(4, until: deadline)
        let size = header.reduce(0) { ($0 << 8) | Int($1) }
        guard size > 0, size <= frameLimit else { throw BridgeError.refused }
        let data = try exact(size, until: deadline)
        guard let message = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let type = message["type"] as? String,
              ["attached", "state", "call", "response", "error"].contains(type) else { throw BridgeError.refused }
        return message
    }

    func send(_ message: [String: Any]) throws {
        guard writeLock.try() else { throw BridgeError.refused }
        defer { writeLock.unlock() }
        let data = try jsonData(message)
        let length = UInt32(data.count)
        let frame = Data([UInt8(length >> 24), UInt8((length >> 16) & 255),
                          UInt8((length >> 8) & 255), UInt8(length & 255)]) + data
        let deadline = now() + 5
        var offset = 0
        while offset < frame.count {
            guard try Self.wait(fd, events: Int16(POLLOUT), until: deadline) else { throw BridgeError.unavailable }
            let count = frame.withUnsafeBytes { raw in
                Darwin.send(fd, raw.baseAddress!.advanced(by: offset), frame.count - offset, 0)
            }
            if count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) { continue }
            guard count > 0 else { throw BridgeError.unavailable }
            offset += count
        }
    }
}

final class BridgeSessions {
    private struct Session {
        let profile: String
        let connection: BrokerConnection
        var touched: Double
    }
    private let lock = NSLock()
    private var sessions: [String: Session] = [:]
    private let socketPath: String

    init(socketPath: String) { self.socketPath = socketPath }

    func close() {
        lock.lock()
        defer { lock.unlock() }
        for session in sessions.values { session.connection.close() }
        sessions.removeAll()
    }

    func handle(_ request: [String: Any], profile: String) -> [String: Any] {
        // Requests contain only sealed messages and opaque transport state.
        do {
            guard let op = request["op"] as? String,
                  let size = try? JSONSerialization.data(withJSONObject: request).count,
                  size <= frameLimit + 512 else { throw BridgeError.refused }
            lock.lock()
            let expired = sessions.filter { now() - $0.value.touched > 60 }.map(\.key)
            for key in expired { sessions.removeValue(forKey: key)?.connection.close() }
            if op == "open" {
                defer { lock.unlock() }
                guard Set(request.keys) == ["op", "hello"], let hello = request["hello"] as? [String: Any],
                      Set(hello.keys).isSubset(of: ["type", "protocol", "public_key", "version", "stale"]),
                      hello["type"] as? String == "hello",
                      let number = hello["protocol"] as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
                      number.intValue == 1, number.doubleValue == 1,
                      let key = hello["public_key"] as? String,
                      key.range(of: "^[A-Za-z0-9_-]{87}$", options: .regularExpression) != nil else {
                    throw BridgeError.refused
                }
                for key in sessions.filter({ $0.value.profile == profile }).map(\.key) {
                    sessions.removeValue(forKey: key)?.connection.close()
                }
                guard sessions.count < 4 else { throw BridgeError.refused }
                var random = [UInt8](repeating: 0, count: 32)
                guard SecRandomCopyBytes(kSecRandomDefault, random.count, &random) == errSecSuccess else {
                    throw BridgeError.unavailable
                }
                let token = random.map { String(format: "%02x", $0) }.joined()
                let connection = try BrokerConnection(path: socketPath)
                var attach: [String: Any] = ["action": "extension-attach", "extension_protocol": 1,
                    "extension_id": "jjoamaejjkldcjcpgncoomoaagdfimhg", "browser": "safari", "public_key": key]
                if let version = hello["version"] { attach["extension_version"] = version }
                if let stale = hello["stale"] { attach["extension_stale"] = stale }
                try connection.send(attach)
                sessions[token] = Session(profile: profile, connection: connection, touched: now())
                return ["ok": true, "session": token]
            }
            guard let token = request["session"] as? String, var session = sessions[token],
                  session.profile == profile else { lock.unlock(); throw BridgeError.refused }
            session.touched = now()
            sessions[token] = session
            if op == "close" {
                sessions.removeValue(forKey: token)
                lock.unlock()
                session.connection.close()
                return ["ok": true]
            }
            lock.unlock()
            do {
                switch op {
                case "read":
                    guard Set(request.keys) == ["op", "session"] else { throw BridgeError.refused }
                    if let message = try session.connection.receive() { return ["ok": true, "message": message] }
                    return ["ok": true]
                case "write":
                    guard Set(request.keys) == ["op", "session", "message"],
                          let message = request["message"] as? [String: Any],
                          let type = message["type"] as? String, ["reply", "request"].contains(type) else {
                        throw BridgeError.refused
                    }
                    try session.connection.send(message)
                    return ["ok": true]
                default: throw BridgeError.refused
                }
            } catch {
                lock.lock()
                sessions.removeValue(forKey: token)?.connection.close()
                lock.unlock()
                throw error
            }
        } catch {
            return ["ok": false, "error": "local broker unavailable"]
        }
    }
}
