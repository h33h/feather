import Foundation
import CryptoKit
import Security

/// Encrypted, backup-excluded private storage. The wrapping key never leaves Keychain.
@MainActor final class ISignProtectedVault: ISignVault {
    private let service = "dev.h33h.feather.isign.v1"
    let root: URL
    init() throws {
        root = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true).appendingPathComponent("iSign", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication])
        var url = root; var values = URLResourceValues(); values.isExcludedFromBackup = true; try url.setResourceValues(values)
        // Crash recovery: staging is exclusively app-owned and never persisted for reuse.
        try? FileManager.default.removeItem(at: root.appendingPathComponent("Staging"))
    }
    private func key(create: Bool) throws -> SymmetricKey? {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: "cache-key", kSecReturnData as String: true]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecSuccess, let data = result as? Data { return SymmetricKey(data: data) }
        guard status == errSecItemNotFound else { throw ISignFailure(code: "KEYCHAIN_UNAVAILABLE") }
        guard create else { return nil }
        let key = SymmetricKey(size: .bits256)
        let data = key.withUnsafeBytes { Data($0) }
        let insert: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: "cache-key", kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, kSecValueData as String: data]
        guard SecItemAdd(insert as CFDictionary, nil) == errSecSuccess else { throw ISignFailure(code: "KEYCHAIN_UNAVAILABLE") }
        return key
    }
    func read(_ name: String) throws -> Data? {
        if name == "session" { return try readSession() }
        guard let key = try key(create: false) else { return nil }
        return try ISignEncryptedCache(root: root).read(name, key: key)
    }
    func write(_ data: Data, key name: String) throws {
        if name == "session" { try writeSession(data); return }
        guard let key = try key(create: true) else { throw ISignFailure(code: "CACHE_UNAVAILABLE") }
        try ISignEncryptedCache(root: root).write(data, name: name, key: key)
    }
    private func readSession() throws -> Data? {
        var result: CFTypeRef?
        let status = SecItemCopyMatching([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: "session", kSecReturnData as String: true] as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else { throw ISignFailure(code: "KEYCHAIN_UNAVAILABLE") }
        return data
    }
    private func writeSession(_ data: Data) throws {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: "session"]
        let status = SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if status == errSecItemNotFound {
            var insert = query
            insert[kSecValueData as String] = data
            insert[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            guard SecItemAdd(insert as CFDictionary, nil) == errSecSuccess else { throw ISignFailure(code: "KEYCHAIN_UNAVAILABLE") }
        } else if status != errSecSuccess { throw ISignFailure(code: "KEYCHAIN_UNAVAILABLE") }
    }
    func clear() throws {
        // Destroy the encryption key even when a file cannot be removed.
        let status = SecItemDelete([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service] as CFDictionary)
        for url in try FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: nil) { try FileManager.default.removeItem(at: url) }
        guard status == errSecSuccess || status == errSecItemNotFound else { throw ISignFailure(code: "KEYCHAIN_UNAVAILABLE") }
    }
    func clearSigning() throws {
        // Every encrypted file here is signing material except selected device IDs.
        // Session tokens live in a separate Keychain item; source rows live in CoreData.
        let devices = try? read("selected-devices")
        let status = SecItemDelete([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: "cache-key"] as CFDictionary)
        for url in try FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: nil) { try FileManager.default.removeItem(at: url) }
        guard status == errSecSuccess || status == errSecItemNotFound else { throw ISignFailure(code: "KEYCHAIN_UNAVAILABLE") }
        if let devices { try write(devices, key: "selected-devices") }
    }
    func stage() throws -> URL {
        let url = root.appendingPathComponent("Staging").appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true, attributes: [.protectionKey: FileProtectionType.complete])
        return url
    }
}

/// Refuse API redirects rather than ever forwarding a bearer to another origin.
final class ISignHTTPTransport: NSObject, ISignTransport, URLSessionTaskDelegate, @unchecked Sendable {
    private var session: URLSession!
    override init() {
        super.init()
        session = URLSession(configuration: .ephemeral, delegate: self, delegateQueue: nil)
    }
    func send(_ request: URLRequest) async throws -> ISignResponse {
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw ISignFailure(code: "INVALID_RESPONSE") }
        return .init(data: data, status: http.statusCode)
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) { completionHandler(nil) }
}
