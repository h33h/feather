import XCTest
import CryptoKit
@testable import ISignCore
final class EncryptedCacheTests: XCTestCase {
    func testReplacementAndAuthenticationWithoutUserKeychain() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let cache = ISignEncryptedCache(root: root), key = SymmetricKey(size: .bits256)
        let secret = Data("private P12 and password".utf8)
        try cache.write(secret, name: "bundle", key: key)
        XCTAssertEqual(try cache.read("bundle", key: key), secret)
        let files = try FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: nil)
        XCTAssertEqual(files.count, 1)
        XCTAssertNil(try Data(contentsOf: files[0]).range(of: secret))
        XCTAssertThrowsError(try cache.read("bundle", key: SymmetricKey(size: .bits256)))
        try cache.write(Data("replacement".utf8), name: "bundle", key: key)
        XCTAssertEqual(try cache.read("bundle", key: key), Data("replacement".utf8))
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: nil).count, 1)
        var bytes = try Data(contentsOf: files[0]); bytes[bytes.count - 1] ^= 1
        try bytes.write(to: files[0]); XCTAssertThrowsError(try cache.read("bundle", key: key))
    }
}
