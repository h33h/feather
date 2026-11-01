import XCTest
@testable import ISignCore

@MainActor final class MemoryVault: ISignVault {
    var values: [String: Data] = [:]
    var failSigningClear = false
    func read(_ key: String) throws -> Data? { values[key] }
    func write(_ data: Data, key: String) throws { values[key] = data }
    func clear() throws { values.removeAll() }
    func clearSigning() throws {
        if failSigningClear { throw ISignFailure(code: "TEST_STORAGE_UNAVAILABLE") }
        values = values.filter { !ISignSigningAuthority.isMaterial($0.key) }
    }
}
actor DelayedTransport: ISignTransport {
    var pending: [String: CheckedContinuation<ISignResponse, Error>] = [:]
    var counts: [String: Int] = [:]
    var requests: [String: URLRequest] = [:]
    func send(_ request: URLRequest) async throws -> ISignResponse {
        let path = request.url!.lastPathComponent
        counts[path, default: 0] += 1
        requests[path] = request
        return try await withCheckedThrowingContinuation { pending[path] = $0 }
    }
    func respond(_ path: String, _ data: Data, status: Int = 200) { pending.removeValue(forKey: path)?.resume(returning: .init(data: data, status: status)) }
    func fail(_ path: String, _ error: Error) { pending.removeValue(forKey: path)?.resume(throwing: error) }
    func wait(_ path: String) async { while pending[path] == nil { await Task.yield() } }
    func count(_ path: String) -> Int { counts[path, default: 0] }
    func request(_ path: String) -> URLRequest? { requests[path] }
}
@MainActor final class SessionTests: XCTestCase {
    let token = ISignTokens(accessToken: "a", refreshToken: "r", tokenType: "Bearer", expiresAt: 0, refreshExpiresAt: 9999999999999, sessionId: "s")
    func client(_ transport: DelayedTransport, _ vault: MemoryVault) throws -> ISignClient {
        let client = try ISignClient(server: URL(string: "https://example.test")!, vault: vault, transport: transport)
        try client.install(tokens: token, owner: .init(ownerId: "one", role: "user", loginName: "One", publicProfileId: "p", sessionId: "s", verifiedAt: 0, expiresAt: 9999999999999))
        return client
    }
    func testRefreshSingleFlightAndLateRefreshCannotRestoreLogout() async throws {
        let transport = DelayedTransport(), vault = MemoryVault(), client = try client(transport, vault)
        let first = Task { try await client.accessToken() }; let second = Task { try await client.accessToken() }
        await transport.wait("refresh")
        for _ in 0..<20 { await Task.yield() }
        let count = await transport.count("refresh"); XCTAssertEqual(count, 1)
        let logout = Task { await client.logout() }
        await transport.wait("logout")
        XCTAssertNil(client.owner)
        await transport.respond("refresh", try JSONEncoder().encode(token))
        for task in [first, second] { do { _ = try await task.value; XCTFail("Late refresh accepted") } catch {} }
        await transport.respond("logout", Data("{}".utf8)); await logout.value
        XCTAssertTrue(vault.values.isEmpty); XCTAssertNil(client.owner)
    }
    func testLateBundleAndSourcesCannotRepopulateAfterOwnerReplacementOrClear() async throws {
        for path in ["signing/bundle", "sources"] {
            for operation in ["replace", "clear"] {
                let transport = DelayedTransport(), vault = MemoryVault(), client = try client(transport, vault)
                var fresh = token; fresh.expiresAt = 9999999999999
                try client.install(tokens: fresh, owner: client.owner!)
                let generation = client.generation
                let task = Task {
                    let data = try await client.raw(path)
                    try client.cache(data, key: "asset", generation: generation)
                }
                await transport.wait(path.components(separatedBy: "/").last!)
                switch operation {
                case "replace":
                    var owner = client.owner!; owner.ownerId = "two"
                    try client.install(tokens: fresh, owner: owner)
                default: try client.clear()
                }
                await transport.respond(path.components(separatedBy: "/").last!, Data("{}".utf8))
                do { try await task.value; XCTFail("Late asset accepted") } catch {}
                XCTAssertNil(try client.cached("asset"))
                XCTAssertEqual(client.owner?.ownerId, operation == "replace" ? "two" : nil)
            }
        }
    }
    func testCallbackRequiresExactEndpointStateAndTransaction() throws {
        let pending = ISignPKCE(state: "state", verifier: "verifier")
        XCTAssertEqual(try pending.code(from: URL(string: "isign-feather://auth/callback?state=state&transactionId=t&code=c")!, transaction: "t"), "c")
        for url in ["isign-feather://auth/other?state=state&transactionId=t&code=c", "isign-feather://auth/callback?state=bad&transactionId=t&code=c", "isign-feather://auth/callback?state=state&transactionId=other&code=c", "isign-feather://auth/callback?state=state&state=state&transactionId=t&code=c"] {
            XCTAssertThrowsError(try pending.code(from: URL(string: url)!, transaction: "t"))
        }
    }
    func testDownloadRequiresExactHTTPSHostAndPort() throws {
        let policy = try ISignDownloadPolicy(URL(string: "https://cdn.test:8443/app?token=a")!)
        XCTAssertTrue(policy.allows(URL(string: "https://cdn.test:8443/other")!))
        for url in ["http://cdn.test:8443/app", "https://cdn.test/app", "https://other.test:8443/app", "https://u:p@cdn.test:8443/app"] { XCTAssertFalse(policy.allows(URL(string: url)!)) }
    }
    func testUnauthorizedClearsButTransientFailurePreservesCache() async throws {
        for status in [401, 503] {
            let transport = DelayedTransport(), vault = MemoryVault(), client = try client(transport, vault)
            var fresh = token; fresh.expiresAt = 9999999999999
            try client.install(tokens: fresh, owner: client.owner!)
            try client.cacheSigning(Data("asset".utf8), key: "bundle", scope: client.signingScope)
            let task = Task { try await client.raw("session") }
            await transport.wait("session")
            let request = await transport.request("session")
            XCTAssertEqual(request?.value(forHTTPHeaderField: "Authorization"), "Bearer a")
            XCTAssertEqual(request?.url?.absoluteString, "https://example.test/api/native/v1/session")
            await transport.respond("session", Data(#"{"code":"UNAVAILABLE"}"#.utf8), status: status)
            do { _ = try await task.value; XCTFail("HTTP error accepted") } catch {}
            if status == 401 { XCTAssertTrue(vault.values.isEmpty); XCTAssertNil(client.owner) }
            else { XCTAssertEqual(try client.cached("bundle"), Data("asset".utf8)); XCTAssertNotNil(client.owner) }
        }
    }
    func testSuccessfulRefreshIsSharedAndPersisted() async throws {
        let transport = DelayedTransport(), vault = MemoryVault(), client = try client(transport, vault)
        let first = Task { try await client.accessToken() }; let second = Task { try await client.accessToken() }
        await transport.wait("refresh")
        for _ in 0..<20 { await Task.yield() }
        var renewed = token; renewed.accessToken = "new"; renewed.refreshToken = "rotated"; renewed.expiresAt = 9999999999999
        await transport.respond("refresh", try JSONEncoder().encode(renewed))
        let a = try await first.value, b = try await second.value
        XCTAssertEqual(a, "new"); XCTAssertEqual(b, "new")
        let count = await transport.count("refresh"); XCTAssertEqual(count, 1)
        let restored = try ISignClient(server: URL(string: "https://example.test")!, vault: vault, transport: transport)
        let restoredToken = try await restored.accessToken(); XCTAssertEqual(restoredToken, "new")
        let request = await transport.request("refresh")
        XCTAssertNil(request?.value(forHTTPHeaderField: "Authorization"))
    }
    func testPKCEChallengeUsesS256() {
        XCTAssertEqual(ISignPKCE(state: "s", verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk").challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
    }
    func testOwnerReplacementClearsOnlyManagedVault() throws {
        let transport = DelayedTransport(), vault = MemoryVault(), client = try client(transport, vault)
        try client.cacheSigning(Data("old".utf8), key: "bundle", scope: client.signingScope)
        var owner = client.owner!; owner.ownerId = "two"
        try client.install(tokens: token, owner: owner)
        XCTAssertNil(try client.cached("bundle")); XCTAssertEqual(client.owner?.ownerId, "two")
    }

    func testConnectionResetRejectsLateAssetButPreservesSession() async throws {
        let transport = DelayedTransport(), vault = MemoryVault(), client = try client(transport, vault)
        var fresh = token; fresh.expiresAt = 9999999999999
        try client.install(tokens: fresh, owner: client.owner!)
        let scope = client.signingScope
        let task = Task {
            let data = try await client.raw("signing/bundle", method: "POST", body: [:])
            try client.cacheSigning(data, key: "bundle", scope: scope)
        }
        await transport.wait("bundle")
        try client.invalidateSigning()
        await transport.respond("bundle", Data("old".utf8))
        do { try await task.value; XCTFail("Old connection asset accepted") } catch {}
        XCTAssertNil(try client.cached("bundle")); XCTAssertEqual(client.owner?.ownerId, "one")
        let token = try await client.accessToken(); XCTAssertEqual(token, "a")
    }

    func testMissingSessionPurgesOrphanedAssetsBeforeNewLogin() throws {
        let vault = MemoryVault(); vault.values["bundle"] = Data("previous owner".utf8)
        _ = try ISignClient(server: URL(string: "https://example.test")!, vault: vault, transport: DelayedTransport())
        XCTAssertTrue(vault.values.isEmpty)
    }

    func testSessionWithoutSigningAuthorityMarkerCannotRestoreCachedMaterial() throws {
        let transport = DelayedTransport(), vault = MemoryVault(), client = try client(transport, vault)
        try client.cacheSigning(Data("private".utf8), key: "bundle", scope: client.signingScope)
        var saved = try XCTUnwrap(JSONSerialization.jsonObject(with: XCTUnwrap(vault.values["session"])) as? [String: Any])
        saved.removeValue(forKey: "signingInvalidated")
        vault.values["session"] = try JSONSerialization.data(withJSONObject: saved)

        let restored = try ISignClient(server: URL(string: "https://example.test")!, vault: vault, transport: transport)
        XCTAssertNil(restored.owner)
        XCTAssertNil(try restored.cached("bundle"))
        XCTAssertTrue(vault.values.isEmpty)
    }

    func testLogoutCanRevokeExpiredAccessWithoutRestoringTokens() async throws {
        let transport = DelayedTransport(), vault = MemoryVault(), client = try client(transport, vault)
        let logout = Task { await client.logout() }
        await transport.wait("logout"); XCTAssertNil(client.owner)
        await transport.respond("logout", Data("{}".utf8), status: 401)
        await transport.wait("refresh")
        var renewed = token; renewed.accessToken = "for-logout-only"
        await transport.respond("refresh", try JSONEncoder().encode(renewed))
        await transport.wait("logout")
        let request = await transport.request("logout")
        XCTAssertEqual(request?.value(forHTTPHeaderField: "Authorization"), "Bearer for-logout-only")
        await transport.respond("logout", Data("{}".utf8))
        await logout.value
        XCTAssertTrue(vault.values.isEmpty); XCTAssertNil(client.owner)
    }

}
