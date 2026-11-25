// Disposable native IPC proof; not included in the shipped app.
import Foundation
import Darwin

@main struct ClientMain {
    static func main() throws {
        let connection = NSXPCConnection(serviceName: "org.akdbx.safari.bridge-probe")
        connection.remoteObjectInterface = NSXPCInterface(with: NativeBridgeProbe.self)
        connection.resume()
        defer { connection.invalidate() }
        while let line = readLine() {
            guard line.utf8.count <= 66048 else { exit(2) }
            let completed = DispatchSemaphore(value: 0)
            let proxy = connection.remoteObjectProxyWithErrorHandler { error in
                // Native errors contain no request values; print only a code.
                print("{\"ok\":false,\"xpc_code\":\((error as NSError).code)}")
                fflush(stdout)
                completed.signal()
            } as! NativeBridgeProbe
            proxy.request(Data(line.utf8)) { result in
                if result.count <= 66048, let value = String(data: result, encoding: .utf8) {
                    print(value)
                    fflush(stdout)
                }
                completed.signal()
            }
            guard completed.wait(timeout: .now() + 8) == .success else { exit(3) }
        }
    }
}
