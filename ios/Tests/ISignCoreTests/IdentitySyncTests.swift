import XCTest
@testable import ISignCore

@MainActor final class IdentitySyncTests: XCTestCase {
    func client(_ transport: DelayedTransport, _ vault: MemoryVault) throws -> ISignClient {
        let client = try ISignClient(server: URL(string: "https://example.test")!, vault: vault, transport: transport)
        try client.install(tokens: .init(accessToken: "a", refreshToken: "r", tokenType: "Bearer", expiresAt: 9999999999999, refreshExpiresAt: 9999999999999, sessionId: "s"), owner: .init(ownerId: "owner", role: "user", loginName: "Owner", publicProfileId: "p", sessionId: "s", verifiedAt: 9999999999999, expiresAt: 9999999999999))
        return client
    }
    func coordinator(_ client: ISignClient, polls: Int = 3, phases: @escaping (ISignIdentityPhase) -> Void = { _ in }) -> ISignIdentitySync {
        weak var handle: ISignIdentitySync?
        let sync = ISignIdentitySync(client: client, pollLimit: polls, pause: {}, onIdentity: { _ in }, onPhase: phases, onReady: { _, scope in
            if try client.cached("bundle") == nil {
                let data = try await client.raw("signing/bundle", method: "POST", body: [:])
                guard let handle else { throw CancellationError() }
                try handle.check(scope)
                try client.cacheSigning(data, key: "bundle", scope: scope.signing)
            }
        })
        handle = sync
        return sync
    }
    func response(_ state: String, renewal: String? = nil) -> Data {
        Data(("{\"state\":\"\(state)\",\"connectionId\":\"c\",\"connectionGeneration\":1,\"teamId\":\"TEAM123456\",\"identityId\":\"i\",\"revision\":1,\"certificateSha256\":\"digest\",\"expiresAt\":9999999999999" + (renewal.map { ",\"renewal\":{\"identityId\":\"replacement\",\"state\":\"\($0)\"}" } ?? "") + "}").utf8)
    }
    func testReconciliationAutomaticallyCachesBundleAndNeverUsesRetry() async throws {
        let transport = DelayedTransport(), vault = MemoryVault(), client = try client(transport, vault)
        var phases: [ISignIdentityPhase] = []
        let sync = coordinator(client, phases: { phases.append($0) })
        let work = Task { try await sync.reconcile() }
        await transport.wait("ensure"); await transport.respond("ensure", response("reconciling"))
        await transport.wait("identity"); XCTAssertEqual(phases.last, .preparing)
        await transport.respond("identity", response("ready"))
        await transport.wait("bundle"); await transport.respond("bundle", Data("asset".utf8))
        let result = try await work.value
        XCTAssertEqual(result, .ready); XCTAssertEqual(try client.cached("bundle"), Data("asset".utf8))
        let request = await transport.request("ensure")
        XCTAssertEqual(try JSONSerialization.jsonObject(with: request!.httpBody!) as? [String: Bool], [:])
    }
    func testOwnerReplacementAndResetRejectLateReconciliationAndBundle() async throws {
        for path in ["identity", "bundle"] {
            for operation in ["replace", "reset", "clear"] {
                let transport = DelayedTransport(), vault = MemoryVault(), client = try client(transport, vault)
                let sync = coordinator(client); let work = Task { try await sync.reconcile() }
                await transport.wait("ensure"); await transport.respond("ensure", response(path == "identity" ? "reconciling" : "ready"))
                await transport.wait(path)
                switch operation {
                case "replace":
                    var owner = client.owner!; owner.ownerId = "replacement"
                    try client.install(tokens: .init(accessToken: "new", refreshToken: "new", tokenType: "Bearer", expiresAt: 9999999999999, refreshExpiresAt: 9999999999999, sessionId: "s"), owner: owner)
                case "reset": try client.invalidateSigning()
                default: try client.clear()
                }
                sync.cancel()
                await transport.respond(path, path == "identity" ? response("ready") : Data("old".utf8))
                do { _ = try await work.value; XCTFail("Late result accepted") } catch {}
                XCTAssertNil(try client.cached("bundle"))
                XCTAssertEqual(client.owner?.ownerId, operation == "replace" ? "replacement" : operation == "reset" ? "owner" : nil)
            }
        }
    }
    func testTerminalStatesStopWithoutFetchingBundle() async throws {
        for state in ["action_required", "revoked"] {
            let transport = DelayedTransport(), vault = MemoryVault(), client = try client(transport, vault)
            let sync = coordinator(client); let work = Task { try await sync.reconcile() }
            await transport.wait("ensure"); await transport.respond("ensure", response(state))
            let result = try await work.value
            XCTAssertEqual(result, state == "revoked" ? .revoked : .actionRequired)
            let count = await transport.count("bundle"); XCTAssertEqual(count, 0)
            let polls = await transport.count("identity"); XCTAssertEqual(polls, 0)
        }
    }
    func testBoundedPreparationResumesOnNextForegroundReconciliation() async throws {
        let transport = DelayedTransport(), vault = MemoryVault(), client = try client(transport, vault)
        let sync = coordinator(client, polls: 1)
        let first = Task { try await sync.reconcile() }
        await transport.wait("ensure"); await transport.respond("ensure", response("reconciling"))
        let pending = try await first.value; XCTAssertEqual(pending, .preparing)
        let resumed = Task { try await sync.reconcile() }
        await transport.wait("ensure"); await transport.respond("ensure", response("ready"))
        await transport.wait("bundle"); await transport.respond("bundle", Data("ready".utf8))
        let result = try await resumed.value; XCTAssertEqual(result, .ready)
    }
    func testBackgroundCancellationCannotCacheLateBundleAndCanResume() async throws {
        let transport = DelayedTransport(), vault = MemoryVault(), client = try client(transport, vault)
        let sync = coordinator(client)
        let work = Task { try await sync.reconcile() }
        await transport.wait("ensure"); await transport.respond("ensure", response("ready"))
        await transport.wait("bundle"); sync.cancel()
        await transport.respond("bundle", Data("cancelled".utf8))
        do { _ = try await work.value; XCTFail("Cancelled result accepted") } catch {}
        XCTAssertNil(try client.cached("bundle")); XCTAssertNotNil(client.owner)
        let resumed = Task { try await sync.reconcile() }
        await transport.wait("ensure"); await transport.respond("ensure", response("ready"))
        await transport.wait("bundle"); await transport.respond("bundle", Data("resumed".utf8))
        _ = try await resumed.value
        XCTAssertEqual(try client.cached("bundle"), Data("resumed".utf8))
    }
    func testRenewalKeepsCurrentBundleWhilePollingAndStopsAtOwnerAction() async throws {
        let transport = DelayedTransport(), vault = MemoryVault(), client = try client(transport, vault)
        try client.cacheSigning(Data("current".utf8), key: "bundle", scope: client.signingScope)
        let sync = coordinator(client); let work = Task { try await sync.reconcile() }
        await transport.wait("ensure"); await transport.respond("ensure", response("ready", renewal: "reconciling"))
        await transport.wait("identity"); XCTAssertEqual(try client.cached("bundle"), Data("current".utf8))
        await transport.respond("identity", response("ready", renewal: "action_required"))
        let result = try await work.value; XCTAssertEqual(result, .ready)
        let bundles = await transport.count("bundle"); XCTAssertEqual(bundles, 0)
    }
    func testManagedSelectionNeverSelectsManualRow() {
        let managed = ISignCertificateSelection(managed: true, manualIndex: 2)
        XCTAssertEqual(managed, .managed)
        XCTAssertFalse(managed.isManualSelected(2))
        let manual = ISignCertificateSelection(managed: false, manualIndex: 2)
        XCTAssertTrue(manual.isManualSelected(2)); XCTAssertFalse(manual.isManualSelected(1))
    }
    func testConcurrentSyncCallsShareOneReconciliation() async throws {
        let transport = DelayedTransport(), vault = MemoryVault(), client = try client(transport, vault)
        let sync = coordinator(client)
        let first = Task { try await sync.reconcile() }, second = Task { try await sync.reconcile() }
        await transport.wait("ensure")
        for _ in 0..<20 { await Task.yield() }
        let requests = await transport.count("ensure"); XCTAssertEqual(requests, 1)
        await transport.respond("ensure", response("action_required"))
        let a = try await first.value, b = try await second.value
        XCTAssertEqual(a, .actionRequired); XCTAssertEqual(b, .actionRequired)
    }

    func testNativeTransportCancellationIsQuietLifecycleCancellation() async throws {
        let transport = DelayedTransport(), vault = MemoryVault(), client = try client(transport, vault)
        let sync = coordinator(client); let work = Task { try await sync.reconcile() }
        await transport.wait("ensure"); sync.cancel()
        await transport.fail("ensure", URLError(.cancelled))
        do { _ = try await work.value; XCTFail("Cancelled sync succeeded") }
        catch { XCTAssertTrue(error is CancellationError) }
    }

}
