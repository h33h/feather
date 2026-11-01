import Foundation
import CryptoKit

/// Portable encrypted file primitive; callers provide a device-only Keychain key.
struct ISignEncryptedCache {
    let root: URL
    private func url(_ name: String) -> URL { root.appendingPathComponent(SHA256.hash(data: Data(name.utf8)).map { String(format: "%02x", $0) }.joined() + ".sealed") }
    func read(_ name: String, key: SymmetricKey) throws -> Data? {
        guard FileManager.default.fileExists(atPath: url(name).path) else { return nil }
        return try AES.GCM.open(AES.GCM.SealedBox(combined: Data(contentsOf: url(name))), using: key, authenticating: Data(name.utf8))
    }
    func write(_ data: Data, name: String, key: SymmetricKey) throws {
        guard let encrypted = try AES.GCM.seal(data, using: key, authenticating: Data(name.utf8)).combined else { throw ISignFailure(code: "CACHE_UNAVAILABLE") }
        #if os(iOS)
        try encrypted.write(to: url(name), options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        #else
        try encrypted.write(to: url(name), options: .atomic)
        #endif
    }
}
