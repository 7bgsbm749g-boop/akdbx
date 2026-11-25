// Disposable native IPC proof; not included in the shipped app.
import Foundation

@objc protocol NativeBridgeProbe {
    func request(_ data: Data, reply: @escaping (Data) -> Void)
}
