import Foundation

struct ISignResponse: Sendable { let data: Data; let status: Int }
protocol ISignTransport: Sendable { func send(_ request: URLRequest) async throws -> ISignResponse }
@MainActor protocol ISignVault {
    func read(_ key: String) throws -> Data?
    func write(_ data: Data, key: String) throws
    func clear() throws
    func clearSigning() throws
}
/// All state commits are synchronous on this actor, immediately after a generation check.
/// Transport completion, including refresh, can never restore a cleared owner.
struct ISignSigningScope {
    let generation: UUID
    let authority: UUID
}
enum ISignSigningAuthority {
    static let terminalErrors: Set<String> = ["APPLE_ACCESS_UNAVAILABLE", "APPLE_ACCESS_CHANGED", "CERTIFICATE_NOT_CURRENT"]
    static func isMaterial(_ key: String) -> Bool { ["bundle", "bundle-history", "profile-request"].contains(key) || key.hasPrefix("profiles:") }
}
@MainActor final class ISignClient {
    private(set) var server: URL
    private(set) var generation = UUID()
    private(set) var signingGeneration = UUID()
    var signingScope: ISignSigningScope { .init(generation: generation, authority: signingGeneration) }
    private(set) var owner: ISignOwner?
    private var tokens: ISignTokens?
    private var signingCacheInvalidated = false
    private var refreshing: Task<ISignTokens, Error>?
    private var signingRequests: Set<UUID> = []
    private var inFlight: [UUID: Task<ISignResponse, Error>] = [:]
    private let vault: ISignVault
    private let transport: ISignTransport
    var onClear: (() -> Void)?
    var onSigningInvalidated: (() -> Void)?
    init(server: URL, vault: ISignVault, transport: ISignTransport) throws {
        try Self.validate(server)
        self.server = server; self.vault = vault; self.transport = transport
        if let saved = try vault.read("session") {
            if let session = try? JSONDecoder().decode(Saved.self, from: saved), session.server == server.absoluteString {
                owner = session.owner; tokens = session.tokens
                signingCacheInvalidated = session.signingInvalidated ?? false
            } else { try vault.clear() }
        } else { try vault.clear() }
    }
    private struct Saved: Codable { let server: String; let owner: ISignOwner; let tokens: ISignTokens; let signingInvalidated: Bool? }
    private func saveSession(tokens: ISignTokens, owner: ISignOwner) throws {
        try vault.write(JSONEncoder().encode(Saved(server: server.absoluteString, owner: owner, tokens: tokens, signingInvalidated: signingCacheInvalidated)), key: "session")
    }
    static func validate(_ url: URL) throws {
        guard url.scheme == "https", url.host != nil, url.user == nil, url.password == nil, url.query == nil, url.fragment == nil, url.path.isEmpty || url.path == "/" else { throw ISignFailure(code: "HTTPS_ORIGIN_REQUIRED") }
    }
    func check(_ generation: UUID) throws { guard self.generation == generation else { throw ISignFailure(code: "STALE_SESSION") } }
    func checkSigning(_ scope: ISignSigningScope) throws {
        try check(scope.generation)
        guard signingGeneration == scope.authority else { throw ISignFailure(code: "STALE_SIGNING_AUTHORITY") }
    }
    func invalidateSigning() throws {
        signingGeneration = UUID(); signingCacheInvalidated = true
        for id in signingRequests { inFlight[id]?.cancel() }
        onSigningInvalidated?()
        // Keep a denial marker with the account even if private-file deletion fails.
        var markerError: Error?
        do { if let tokens, let owner { try saveSession(tokens: tokens, owner: owner) } }
        catch { markerError = error }
        try vault.clearSigning()
        if let markerError { throw markerError }
    }
    func observeIdentity(_ identity: ISignIdentity) throws {
        // Ready + renewal metadata still authorizes the current certificate.
        if identity.state != "ready" { try invalidateSigning() }
    }
    func install(tokens: ISignTokens, owner: ISignOwner) throws {
        guard tokens.tokenType == "Bearer", tokens.sessionId == owner.sessionId else { throw ISignFailure(code: "INVALID_SESSION") }
        if let old = self.owner, old.ownerId != owner.ownerId || old.sessionId != owner.sessionId { try clear() }
        try saveSession(tokens: tokens, owner: owner)
        self.tokens = tokens; self.owner = owner
    }
    func clear() throws {
        generation = UUID(); signingGeneration = UUID(); signingCacheInvalidated = false; refreshing?.cancel(); refreshing = nil; owner = nil; tokens = nil
        for task in inFlight.values { task.cancel() }; inFlight.removeAll(); signingRequests.removeAll()
        onClear?()
        try vault.clear()
    }
    func resetManaged() throws {
        let savedTokens = tokens, savedOwner = owner
        try clear()
        if let savedTokens, let savedOwner { try install(tokens: savedTokens, owner: savedOwner) }
    }
    func changeServer(_ server: URL) throws { try Self.validate(server); try clear(); self.server = server }
    func accessToken() async throws -> String {
        let stamp = generation
        guard let token = tokens else { throw ISignFailure(code: "AUTH_REQUIRED") }
        if token.expiresAt > Date().timeIntervalSince1970 * 1000 + 30000 { return token.accessToken }
        let task: Task<ISignTokens, Error>
        if let existing = refreshing { task = existing } else {
            task = Task { try await self.publicRequest("auth/refresh", body: ["refreshToken": token.refreshToken]) }
            refreshing = task
        }
        do {
            let updated = try await task.value
            try check(stamp)
            guard let owner else { throw ISignFailure(code: "STALE_SESSION") }
            try install(tokens: updated, owner: owner)
            refreshing = nil
            return updated.accessToken
        } catch {
            if generation == stamp { refreshing = nil; if let failure = error as? ISignFailure, ["AUTH_REQUIRED", "UNAUTHORIZED", "INVALID_REFRESH", "REFRESH_REPLAY", "NATIVE_SESSION_REVOKED"].contains(failure.code) { try? clear() } }
            throw error
        }
    }
    func raw(_ path: String, method: String = "GET", body: [String: Any]? = nil, authenticated: Bool = true, bearer: String? = nil) async throws -> Data {
        let stamp = generation
        let authority = signingScope
        let isSigningRequest = path.hasPrefix("signing/")
        let access = authenticated ? try await accessToken() : bearer
        try check(stamp)
        if isSigningRequest { try checkSigning(authority) }
        guard !path.contains(".."), !path.hasPrefix("/"), !path.contains("?"), !path.contains("#") else { throw ISignFailure(code: "INVALID_API_PATH") }
        let url = server.appendingPathComponent("api/native/v1").appendingPathComponent(path)
        var request = URLRequest(url: url); request.httpMethod = method
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if let access { request.setValue("Bearer \(access)", forHTTPHeaderField: "Authorization") }
        if let body { request.httpBody = try JSONSerialization.data(withJSONObject: body); request.setValue("application/json", forHTTPHeaderField: "Content-Type") }
        let requestId = UUID()
        let transport = self.transport
        let task = Task { try await transport.send(request) }
        inFlight[requestId] = task
        if isSigningRequest { signingRequests.insert(requestId) }
        defer { inFlight.removeValue(forKey: requestId); signingRequests.remove(requestId) }
        let response = try await withTaskCancellationHandler(operation: { try await task.value }, onCancel: { task.cancel() })
        try check(stamp)
        if response.status == 401 { try clear(); throw ISignFailure(code: "AUTH_REQUIRED") }
        if isSigningRequest { try checkSigning(authority) }
        guard (200..<300).contains(response.status) else {
            let failure = (try? JSONDecoder().decode(ISignFailure.self, from: response.data)) ?? ISignFailure(code: "HTTP_\(response.status)")
            if authenticated && ISignSigningAuthority.terminalErrors.contains(failure.code) { try invalidateSigning() }
            throw failure
        }
        return response.data
    }
    func request<T: Decodable>(_ path: String, method: String = "GET", body: [String: Any]? = nil) async throws -> T {
        let authority = signingScope
        let value = try await JSONDecoder().decode(T.self, from: raw(path, method: method, body: body))
        if path.hasPrefix("signing/") { try checkSigning(authority) }
        if let profiles = value as? ISignProfiles, let reason = profiles.reason, ISignSigningAuthority.terminalErrors.contains(reason) {
            try invalidateSigning(); throw ISignFailure(code: reason)
        }
        return value
    }
    func publicRequest<T: Decodable>(_ path: String, body: [String: Any]) async throws -> T { try await JSONDecoder().decode(T.self, from: raw(path, method: "POST", body: body, authenticated: false)) }
    func fetchAndCache(_ path: String, key: String, method: String = "GET", body: [String: Any]? = nil) async throws {
        let stamp = generation, authority = signingScope
        let data = try await raw(path, method: method, body: body)
        try check(stamp)
        if path.hasPrefix("signing/") || ISignSigningAuthority.isMaterial(key) { try checkSigning(authority) }
        if ISignSigningAuthority.isMaterial(key) { try cacheSigning(data, key: key, scope: authority) }
        else { try cache(data, key: key, generation: stamp) }
    }
    func cache(_ data: Data, key: String, generation: UUID) throws {
        try check(generation)
        guard owner != nil else { throw ISignFailure(code: "AUTH_REQUIRED") }
        guard !ISignSigningAuthority.isMaterial(key) else { throw ISignFailure(code: "SIGNING_SCOPE_REQUIRED") }
        try vault.write(data, key: key)
    }
    func cacheSigning(_ data: Data, key: String, scope: ISignSigningScope) throws {
        try checkSigning(scope)
        guard owner != nil, ISignSigningAuthority.isMaterial(key) else { throw ISignFailure(code: "INVALID_SIGNING_CACHE_SCOPE") }
        if signingCacheInvalidated {
            guard key == "bundle" else { throw ISignFailure(code: "SIGNING_AUTHORITY_UNAVAILABLE") }
            // A fresh validated bundle may restore authority only after every old
            // history/profile is gone, including a previously failed cleanup.
            try vault.clearSigning()
        }
        try vault.write(data, key: key)
        if key == "bundle" && signingCacheInvalidated {
            signingCacheInvalidated = false
            do { if let tokens, let owner { try saveSession(tokens: tokens, owner: owner) } }
            catch { signingCacheInvalidated = true; throw error }
        }
    }
    func cached(_ key: String) throws -> Data? {
        guard owner != nil, !(signingCacheInvalidated && ISignSigningAuthority.isMaterial(key)) else { return nil }
        return try vault.read(key)
    }
    func logout() async {
        // Clear synchronously before networking. Revocation uses only the captured
        // old server/session and can never install a token in a newer owner scope.
        let snapshot = tokens; let oldServer = server
        try? clear()
        guard let snapshot else { return }
        func revoke(_ access: String) async throws -> ISignResponse {
            var request = URLRequest(url: oldServer.appendingPathComponent("api/native/v1/auth/logout"))
            request.httpMethod = "POST"; request.httpBody = Data("{}".utf8)
            request.setValue("Bearer \(access)", forHTTPHeaderField: "Authorization"); request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            return try await transport.send(request)
        }
        guard let result = try? await revoke(snapshot.accessToken), result.status == 401 else { return }
        // An expired access token must not make online logout predictably ineffective.
        // Refresh only to revoke; these tokens are deliberately never persisted.
        var refresh = URLRequest(url: oldServer.appendingPathComponent("api/native/v1/auth/refresh"))
        refresh.httpMethod = "POST"; refresh.setValue("application/json", forHTTPHeaderField: "Content-Type")
        refresh.httpBody = try? JSONSerialization.data(withJSONObject: ["refreshToken": snapshot.refreshToken])
        guard let response = try? await transport.send(refresh), response.status == 200,
              let renewed = try? JSONDecoder().decode(ISignTokens.self, from: response.data),
              renewed.sessionId == snapshot.sessionId, renewed.tokenType == "Bearer" else { return }
        _ = try? await revoke(renewed.accessToken)
    }
}
