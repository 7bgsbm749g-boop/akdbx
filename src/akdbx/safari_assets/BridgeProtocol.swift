import Foundation

@objc protocol LocalBrokerBridge {
    func request(_ data: Data, reply: @escaping (Data) -> Void)
}
