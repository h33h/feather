import XCTest
@testable import ISignCore

@MainActor final class SigningAuthorityTests: XCTestCase {
    let materialKeys = ["bundle", "bundle-history", "profile-request", "profiles:old:1:request", "profiles:new:2:request"]
    func seeded(_ transport: DelayedTransport, _ vault: MemoryVault) throws -> ISignClient {
        let client = try ISignClient(server: URL(string: "https://example.test")!, vault: vault, transport: transport)
        try client.install(tokens: .init(accessToken: "a", refreshToken: "r", tokenType: "Bearer", expiresAt: 9999999999999, refreshExpiresAt: 9999999999999, sessionId: "s"), owner: .init(ownerId: "owner", role: "user", loginName: "Owner", publicProfileId: "p", sessionId: "s", verifiedAt: 0, expiresAt: 9999999999999))
        for key in materialKeys { try client.cacheSigning(Data("private".utf8), key: key, scope: client.signingScope) }
        try client.cache(Data("device".utf8), key: "selected-devices", generation: client.generation)
        return client
    }
    func testKnownAuthorityLossPurgesAllSigningMaterialButKeepsAccountAndSources() async throws {
        for code in ["APPLE_ACCESS_UNAVAILABLE", "APPLE_ACCESS_CHANGED", "CERTIFICATE_NOT_CURRENT"] {
            let transport = DelayedTransport(), vault = MemoryVault(), client = try seeded(transport, vault)
            let ownerGeneration = client.generation
            var globalCleanup = false; client.onClear = { globalCleanup = true }
            let request = Task { try await client.raw("signing/profiles/ensure", method: "POST", body: [:]) }
            await transport.wait("ensure")
            await transport.respond("ensure", Data("{\"code\":\"\(code)\"}".utf8), status: 403)
            do { _ = try await request.value; XCTFail("Known loss accepted") } catch {}
            for key in materialKeys { XCTAssertNil(try client.cached(key), key) }
            XCTAssertEqual(client.owner?.ownerId, "owner"); XCTAssertEqual(client.generation, ownerGeneration)
            XCTAssertEqual(try client.cached("selected-devices"), Data("device".utf8)); XCTAssertFalse(globalCleanup)
            // A subsequent genuine outage cannot resurrect a current/history/profile pair.
            let offline = Task { try await client.raw("signing/identity") }
            await transport.wait("identity"); await transport.fail("identity", URLError(.notConnectedToInternet))
            do { _ = try await offline.value } catch {}
            XCTAssertNil(try client.cached("bundle")); XCTAssertNil(try client.cached("bundle-history"))
        }
    }
    func testDelayedBundleCannotRepopulateAfterKnownAuthorityLoss() async throws {
        let transport = DelayedTransport(), vault = MemoryVault(), client = try seeded(transport, vault)
        let old = Task { try await client.fetchAndCache("signing/bundle", key: "bundle", method: "POST", body: [:]) }
        await transport.wait("bundle")
        let invalidation = Task { try await client.raw("signing/profiles/ensure", method: "POST", body: [:]) }
        await transport.wait("ensure"); await transport.respond("ensure", Data(#"{"code":"CERTIFICATE_NOT_CURRENT"}"#.utf8), status: 409)
        do { _ = try await invalidation.value } catch {}
        await transport.respond("bundle", Data("late".utf8))
        do { try await old.value; XCTFail("Late signing material restored") } catch {}
        XCTAssertNil(try client.cached("bundle")); XCTAssertNotNil(client.owner)
    }
    func testTransientServerAndNetworkFailuresRetainValidOfflineMaterial() async throws {
        for network in [false, true] {
            let transport = DelayedTransport(), vault = MemoryVault(), client = try seeded(transport, vault)
            let request = Task { try await client.raw("signing/identity") }
            await transport.wait("identity")
            if network { await transport.fail("identity", URLError(.notConnectedToInternet)) }
            else { await transport.respond("identity", Data(#"{"code":"SERVICE_UNAVAILABLE"}"#.utf8), status: 503) }
            do { _ = try await request.value } catch {}
            for key in materialKeys { XCTAssertEqual(try client.cached(key), Data("private".utf8)) }
        }
    }
    func testNonreadyIdentityPurgesHistoryAndResumesToFreshBundle() async throws {
        for state in ["missing", "reconciling", "action_required", "revoked"] {
            let transport = DelayedTransport(), vault = MemoryVault(), client = try seeded(transport, vault)
            let result = try JSONDecoder().decode(ISignIdentity.self, from: Data("{\"state\":\"\(state)\"}".utf8))
            let previousScope = client.signingScope
            try client.observeIdentity(result)
            for key in materialKeys { XCTAssertNil(try client.cached(key)) }
            XCTAssertThrowsError(try client.checkSigning(previousScope))
            XCTAssertNotNil(client.owner)
        }
        let transport = DelayedTransport(), vault = MemoryVault(), client = try seeded(transport, vault)
        let sync = ISignIdentitySync(client: client, pollLimit: 2, pause: {}, onIdentity: { _ in }, onPhase: { _ in }, onReady: { _, scope in
            let data = try await client.raw("signing/bundle", method: "POST", body: [:])
            try client.cacheSigning(data, key: "bundle", scope: scope.signing)
        })
        let work = Task { try await sync.reconcile() }
        await transport.wait("ensure"); await transport.respond("ensure", Data(#"{"state":"reconciling"}"#.utf8))
        await transport.wait("identity")
        for key in materialKeys { XCTAssertNil(try client.cached(key)) }
        await transport.respond("identity", Data(#"{"state":"ready"}"#.utf8))
        await transport.wait("bundle"); await transport.respond("bundle", Data("fresh".utf8))
        _ = try await work.value
        XCTAssertEqual(try client.cached("bundle"), Data("fresh".utf8)); XCTAssertNil(try client.cached("bundle-history"))
    }
    func testProfileJournalKnownLossAlsoInvalidatesMaterial() async throws {
        let transport = DelayedTransport(), vault = MemoryVault(), client = try seeded(transport, vault)
        let work = Task { let result: ISignProfiles = try await client.request("signing/profiles/operation"); return result }
        await transport.wait("operation")
        await transport.respond("operation", Data(#"{"operationId":"op","state":"action_required","profiles":[],"reason":"CERTIFICATE_NOT_CURRENT"}"#.utf8))
        do { _ = try await work.value; XCTFail("Known loss hidden in a successful envelope") } catch {}
        for key in materialKeys { XCTAssertNil(try client.cached(key)) }
    }
    func testInvalidationFencesSigningScopeAndLateProfilesButNotIndependentSources() async throws {
        let transport = DelayedTransport(), vault = MemoryVault(), client = try seeded(transport, vault)
        let oldScope = client.signingScope
        let profiles = Task { try await client.fetchAndCache("signing/profiles/operation", key: "profiles:old:1:request") }
        let source = Task { try await client.fetchAndCache("sources/feed", key: "source-cache") }
        await transport.wait("operation"); await transport.wait("feed")
        try client.invalidateSigning()
        XCTAssertThrowsError(try client.cacheSigning(Data("old".utf8), key: "bundle-history", scope: oldScope))
        await transport.respond("operation", Data("old".utf8)); await transport.respond("feed", Data("source".utf8))
        do { try await profiles.value; XCTFail("Old profiles restored") } catch {}
        try await source.value
        XCTAssertEqual(try client.cached("source-cache"), Data("source".utf8))
        XCTAssertNil(try client.cached("profiles:old:1:request")); XCTAssertNotNil(client.owner)
    }

    func testCleanupFailureCannotMakeKnownInvalidMaterialReadableAfterRestart() throws {
        let transport = DelayedTransport(), vault = MemoryVault(), client = try seeded(transport, vault)
        vault.failSigningClear = true
        XCTAssertThrowsError(try client.invalidateSigning())
        XCTAssertNotNil(vault.values["bundle"]) // Simulated removal failure, not a successful purge.
        XCTAssertNil(try client.cached("bundle"))
        let restored = try ISignClient(server: URL(string: "https://example.test")!, vault: vault, transport: transport)
        XCTAssertNil(try restored.cached("bundle")); XCTAssertNil(try restored.cached("bundle-history"))
        XCTAssertNotNil(restored.owner)
        vault.failSigningClear = false
        try restored.cacheSigning(Data("fresh".utf8), key: "bundle", scope: restored.signingScope)
        XCTAssertEqual(try restored.cached("bundle"), Data("fresh".utf8))
        XCTAssertNil(try restored.cached("bundle-history")); XCTAssertNil(try restored.cached("profiles:old:1:request"))
    }

}
