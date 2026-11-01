import Foundation

enum ISignIdentityPhase: Equatable {
    case preparing, renewing, ready, actionRequired, revoked
}
struct ISignIdentityScope {
    let signing: ISignSigningScope
    var generation: UUID { signing.generation }
    fileprivate let run: UUID
}

/// The same bounded reconciliation used by launch, manual sync and foreground resume.
/// Ordinary ensure/status requests never reset an action-required or revoked identity.
@MainActor final class ISignIdentitySync {
    private let client: ISignClient
    private let pollLimit: Int
    private let pause: () async throws -> Void
    private let onIdentity: (ISignIdentity) -> Void
    private let onPhase: (ISignIdentityPhase) -> Void
    private let onReady: (ISignIdentity, ISignIdentityScope) async throws -> Void
    private var epoch = UUID()
    private var running: Task<ISignIdentityPhase, Error>?

    init(client: ISignClient, pollLimit: Int = 20,
         pause: @escaping () async throws -> Void = { try await Task.sleep(nanoseconds: 3_000_000_000) },
         onIdentity: @escaping (ISignIdentity) -> Void,
         onPhase: @escaping (ISignIdentityPhase) -> Void,
         onReady: @escaping (ISignIdentity, ISignIdentityScope) async throws -> Void) {
        self.client = client; self.pollLimit = max(1, pollLimit); self.pause = pause
        self.onIdentity = onIdentity; self.onPhase = onPhase; self.onReady = onReady
    }
    func check(_ scope: ISignIdentityScope) throws {
        try Task.checkCancellation()
        guard epoch == scope.run else { throw CancellationError() }
        try client.checkSigning(scope.signing)
    }
    func cancel() { epoch = UUID(); running?.cancel(); running = nil }
    func reconcile() async throws -> ISignIdentityPhase {
        if let running { return try await running.value }
        let scope = ISignIdentityScope(signing: client.signingScope, run: UUID())
        epoch = scope.run
        let task = Task {
            do { return try await self.perform(scope) }
            catch {
                // URLSession reports URLError.cancelled; lifecycle cancellation must
                // stay quiet rather than surfacing a spurious sync failure.
                if Task.isCancelled || self.epoch != scope.run { throw CancellationError() }
                throw error
            }
        }
        running = task
        defer { if epoch == scope.run { running = nil } }
        return try await task.value
    }
    private func perform(_ initialScope: ISignIdentityScope) async throws -> ISignIdentityPhase {
        var scope = initialScope
        var phase = ISignIdentityPhase.preparing
        for index in 0..<pollLimit {
            try check(scope)
            if index > 0 { try await pause(); try check(scope) }
            let identity: ISignIdentity = index == 0
                ? try await client.request("signing/identity/ensure", method: "POST", body: [:])
                : try await client.request("signing/identity")
            try check(scope)
            try client.observeIdentity(identity)
            // This response authoritatively invalidated prior material. Continue this
            // reconciliation in the new scope; other outstanding signing work is stale.
            scope = ISignIdentityScope(signing: client.signingScope, run: scope.run)
            onIdentity(identity)
            switch identity.state {
            case "ready":
                try await onReady(identity, scope); try check(scope)
                phase = identity.renewal?.state == "reconciling" ? .renewing : .ready
            case "revoked": phase = .revoked
            case "action_required": phase = .actionRequired
            default: phase = .preparing
            }
            onPhase(phase)
            if phase != .preparing && phase != .renewing { return phase }
        }
        return phase // Remains pending; foreground/manual sync resumes ordinary checks.
    }
}

enum ISignCertificateSelection: Equatable {
    case managed, manual(Int)
    init(managed: Bool, manualIndex: Int) { self = managed ? .managed : .manual(manualIndex) }
    func isManualSelected(_ index: Int) -> Bool { self == .manual(index) }
}
