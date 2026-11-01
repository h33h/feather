import Foundation
import SwiftUI
import AuthenticationServices
import AltSourceKit
import Security
import CryptoKit

@MainActor final class ISignStore: NSObject, ObservableObject, ASWebAuthenticationPresentationContextProviding {
    static let shared = ISignStore()
    @Published var owner: ISignOwner?
    @Published var apple: ISignApple?
    @Published var devices: ISignDevices?
    @Published var sources: [ISignSource] = []
    @Published var identity: ISignIdentity?
    @Published var status = String.localized("Not signed in")
    @Published var error: String?
    @Published var busy = false
    @Published var cachedIdentity = false
    @Published var profileOperation: String?
    let vault: ISignProtectedVault?
    private(set) var client: ISignClient?
    private var browser: ASWebAuthenticationSession?
    private var booted = false
    private var identitySync: ISignIdentitySync?
    private var inForeground = true
    private var foregroundResumePending = false
    override init() {
        vault = try? ISignProtectedVault()
        super.init()
        do {
            let server = try ISignServiceConfiguration.server(info: Bundle.main.infoDictionary ?? [:])
            guard let vault else { throw ISignFailure(code: "PROTECTED_STORAGE_UNAVAILABLE") }
            client = try ISignClient(server: server, vault: vault, transport: ISignHTTPTransport())
            attach()
        } catch { self.error = error.localizedDescription }
    }
    private func attach() {
        owner = client?.owner
        client?.onClear = { [weak self] in
            guard let self else { return }
            self.browser?.cancel(); self.browser = nil
            self.identitySync?.cancel(); self.identitySync = nil; self.foregroundResumePending = false
            self.owner = nil; self.apple = nil; self.devices = nil; self.sources = []; self.identity = nil; self.cachedIdentity = false; self.profileOperation = nil
            self.status = .localized("Not signed in")
            UserDefaults.standard.set(false, forKey: "isign.useForSigning")
            self.removeManagedSources()
            DownloadManager.shared.cancelManagedDownloads()
        }
        client?.onSigningInvalidated = { [weak self] in
            self?.cachedIdentity = false; self?.profileOperation = nil; self?.identity = nil
            self?.status = .localized("Signing access changed — synchronize before signing")
        }
        cachedIdentity = (try? cachedBundle()) != nil
    }
    func requireClient() throws -> ISignClient { guard let client else { throw ISignFailure(code: "SERVICE_UNAVAILABLE") }; return client }
    func boot() async {
        guard !booted else { return }; booted = true
        guard owner != nil else { UserDefaults.standard.set(false, forKey: "isign.useForSigning"); removeManagedSources(); return }
        await run { try await self.sync() }
    }
    func run(_ operation: @escaping @MainActor () async throws -> Void) async {
        guard !busy else { return }; busy = true; error = nil
        defer {
            busy = false
            if foregroundResumePending && inForeground {
                foregroundResumePending = false
                Task { await self.foregrounded() }
            }
        }
        do { try await operation() } catch is CancellationError { } catch { self.error = error.localizedDescription }
    }
    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor { UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }.flatMap(\.windows).first(where: \.isKeyWindow) ?? ASPresentationAnchor() }
    func authenticate(stepUp: Bool = false) async throws {
        let client = try requireClient(); let stamp = client.generation; let oldOwner = client.owner?.ownerId
        let pkce = ISignPKCE()
        let body = ["state": pkce.state, "codeChallenge": pkce.challenge, "redirectUri": ISignPKCE.redirect]
        let start: ISignAuthStart = stepUp ? try await client.request("auth/step-up", method: "POST", body: body) : try await client.publicRequest("auth/start", body: body)
        guard try ISignDownloadPolicy(client.server).allows(start.authorizationUrl) else { throw ISignFailure(code: "INVALID_AUTHORIZATION_URL") }
        let callback: URL = try await withCheckedThrowingContinuation { continuation in
            let session = ASWebAuthenticationSession(url: start.authorizationUrl, callbackURLScheme: "isign-feather") { url, error in
                if let url { continuation.resume(returning: url) } else { continuation.resume(throwing: error ?? ISignFailure(code: "AUTH_CANCELLED")) }
            }
            session.presentationContextProvider = self; session.prefersEphemeralWebBrowserSession = true; browser = session
            if !session.start() { browser = nil; continuation.resume(throwing: ISignFailure(code: "AUTH_UNAVAILABLE")) }
        }
        defer { browser = nil }
        try client.check(stamp)
        let code = try pkce.code(from: callback, transaction: start.transactionId)
        let tokens: ISignTokens = try await client.publicRequest("auth/exchange", body: ["transactionId": start.transactionId, "code": code, "codeVerifier": pkce.verifier, "redirectUri": ISignPKCE.redirect])
        let data = try await client.raw("session", authenticated: false, bearer: tokens.accessToken)
        let owner = try JSONDecoder().decode(ISignOwner.self, from: data)
        try client.check(stamp)
        guard !stepUp || oldOwner == owner.ownerId else { throw ISignFailure(code: "OWNER_MISMATCH") }
        try client.install(tokens: tokens, owner: owner); self.owner = owner
        status = .localized("Signed in")
    }
    func fresh() async throws {
        let client = try requireClient()
        if (client.owner?.verifiedAt ?? 0) < Date().timeIntervalSince1970 * 1000 - 240000 { try await authenticate(stepUp: true) }
    }
    func mutate(_ path: String, body: [String: Any] = [:], fresh: Bool = false, method: String = "POST") async throws {
        if fresh { try await self.fresh() }
        let client = try requireClient(); _ = try await client.raw(path, method: method, body: body)
        if ["apple/connect", "apple/disconnect", "signing/identity/revoke"].contains(path) {
            try client.invalidateSigning()
        }
    }
    func sync() async throws {
        let client = try requireClient(); let stamp = client.generation
        let session: ISignOwner = try await client.request("session")
        try client.check(stamp)
        guard session.ownerId == client.owner?.ownerId, session.sessionId == client.owner?.sessionId else { try client.clear(); throw ISignFailure(code: "OWNER_MISMATCH") }
        owner = session
        let apple: ISignApple = try await client.request("apple")
        let devices: ISignDevices = try await client.request("devices")
        let sources: ISignSources = try await client.request("sources")
        try client.check(stamp); self.apple = apple; self.devices = devices; self.sources = sources.sources
        try client.cache(JSONEncoder().encode(devices.devices.filter(\.selected).map(\.id)), key: "selected-devices", generation: stamp)
        try await syncSources(sources.sources, stamp: stamp)
        if apple.connection != nil {
            guard inForeground else { status = .localized("Certificate checks resume when you return to iSign Client"); return }
            let phase = try await reconciliation().reconcile()
            try client.check(stamp)
            if phase == .ready && identity?.renewal == nil { status = error == nil ? .localized("Up to date") : .localized("Synced with warnings") }
        } else {
            identitySync?.cancel()
            try client.invalidateSigning()
            status = .localized("Connect an Apple account to prepare signing")
        }
    }
    func foregrounded() async {
        inForeground = true
        guard booted, owner != nil else { return }
        guard !busy else { foregroundResumePending = true; return }
        await run { try await self.sync() }
    }
    func backgrounded() {
        inForeground = false; foregroundResumePending = false
        identitySync?.cancel()
    }
    private func reconciliation() throws -> ISignIdentitySync {
        if let identitySync { return identitySync }
        let client = try requireClient()
        let sync = ISignIdentitySync(client: client, onIdentity: { [weak self] identity in
            self?.identity = identity
        }, onPhase: { [weak self] phase in
            switch phase {
            case .preparing: self?.status = .localized("Preparing certificate — checks resume when iSign Client is active")
            case .renewing: self?.status = .localized("Certificate update in progress — current certificate remains available")
            case .ready: self?.status = self?.identity?.renewal?.state == "action_required"
                    ? .localized("Current certificate ready — update needs attention") : .localized("Up to date")
            case .actionRequired: self?.status = .localized("Certificate preparation needs attention")
            case .revoked: self?.status = .localized("Client certificate revoked")
            }
        }, onReady: { [weak self] identity, scope in
            guard let self, let coordinator = self.identitySync else { throw CancellationError() }
            try coordinator.check(scope)
            if let bundle = try? self.cachedBundle(), bundle.identityId == identity.identityId,
               bundle.revision == identity.revision, bundle.isValid {
                self.cachedIdentity = true
            } else {
                try await self.syncBundle(guardOperation: { try coordinator.check(scope) })
            }
        })
        identitySync = sync
        return sync
    }
    func cachedBundle() throws -> ISignBundle? {
        guard let data = try client?.cached("bundle"), !data.isEmpty else { return nil }
        let bundle = try JSONDecoder().decode(ISignBundle.self, from: data)
        return bundle.isValid ? bundle : nil
    }
    func syncBundle(guardOperation: () throws -> Void = {}) async throws {
        let client = try requireClient(); let authority = client.signingScope
        try guardOperation()
        try await fresh()
        try client.checkSigning(authority)
        try guardOperation()
        let data = try await client.raw("signing/bundle", method: "POST", body: [:])
        let bundle = try JSONDecoder().decode(ISignBundle.self, from: data)
        try Self.validateP12(bundle)
        try client.checkSigning(authority)
        try guardOperation()
        if let previous = try? cachedBundle(), previous.identityId != bundle.identityId || previous.revision != bundle.revision {
            var history = (try? client.cached("bundle-history").map { try JSONDecoder().decode([ISignBundle].self, from: $0) }) ?? []
            history.removeAll { !$0.isValid || ($0.identityId == previous.identityId && $0.revision == previous.revision) }
            history.append(previous)
            // Commit the previous usable identity before atomically replacing current.
            // Its profiles remain encrypted under their identity/revision/request keys.
            try client.cacheSigning(JSONEncoder().encode(history), key: "bundle-history", scope: authority)
        }
        try client.cacheSigning(data, key: "bundle", scope: authority); cachedIdentity = true
    }
    static func validateP12(_ bundle: ISignBundle) throws {
        guard bundle.isValid, let data = Data(base64Encoded: bundle.p12) else { throw ISignFailure(code: "INVALID_SIGNING_BUNDLE") }
        var options: [String: Any] = [kSecImportExportPassphrase as String: bundle.password]
        if #available(iOS 18, *) { options[kSecImportToMemoryOnly as String] = true }
        var items: CFArray?
        guard SecPKCS12Import(data as CFData, options as CFDictionary, &items) == errSecSuccess,
              let entry = (items as? [[String: Any]])?.first, let value = entry[kSecImportItemIdentity as String] else { throw ISignFailure(code: "INVALID_SIGNING_BUNDLE") }
        let identity = value as! SecIdentity
        var cert: SecCertificate?
        guard SecIdentityCopyCertificate(identity, &cert) == errSecSuccess, let cert else { throw ISignFailure(code: "INVALID_SIGNING_BUNDLE") }
        let digest = SHA256.hash(data: SecCertificateCopyData(cert) as Data).map { String(format: "%02x", $0) }.joined()
        guard digest == bundle.certificateSha256.lowercased() else { throw ISignFailure(code: "CERTIFICATE_MISMATCH") }
    }
    func logout() async { await client?.logout() }
    func exportCertificate(using template: String, generation: UUID) throws {
        let client = try requireClient(); try client.check(generation)
        guard let bundle = try cachedBundle(), template.contains("$(BASE64_CERT)"), template.contains("$(PASSWORD)") else { throw ISignFailure(code: "INVALID_EXPORT_REQUEST") }
        let placeholder = template.replacingOccurrences(of: "$(BASE64_CERT)", with: "certificate").replacingOccurrences(of: "$(PASSWORD)", with: "password")
        guard let target = URL(string: placeholder), let scheme = target.scheme, !["http", "https", "file", "data", "javascript", "isign-feather"].contains(scheme.lowercased()) else { throw ISignFailure(code: "EXTERNAL_APP_CALLBACK_REQUIRED") }
        var allowed = CharacterSet.urlQueryAllowed; allowed.remove(charactersIn: ";/?:@&=+$, ")
        guard let p12 = bundle.p12.addingPercentEncoding(withAllowedCharacters: allowed), let password = bundle.password.addingPercentEncoding(withAllowedCharacters: allowed), let callback = URL(string: template.replacingOccurrences(of: "$(BASE64_CERT)", with: p12).replacingOccurrences(of: "$(PASSWORD)", with: password)) else { throw ISignFailure(code: "INVALID_EXPORT_REQUEST") }
        UIApplication.shared.open(callback)
    }
    func syncSources(_ sources: [ISignSource], stamp: UUID) async throws {
        let client = try requireClient()
        var feeds: [(ISignSource, ASRepository)] = []
        for source in sources where source.state == "ready" {
            do {
                let feed: ISignFeed = try await client.request("sources/\(source.id)/feed")
                try client.check(stamp)
                guard feed.sourceId == source.id else { throw ISignFailure(code: "SOURCE_BINDING_MISMATCH") }
                feeds.append((source, feed.repository))
            } catch {
                try client.check(stamp)
                self.error = error.localizedDescription
            }
        }
        try client.check(stamp)
        let currentIDs = Set(sources.filter { $0.state == "ready" }.map { "isign:\($0.id)" })
        for row in Storage.shared.getSources() where row.isISignManaged && !currentIDs.contains(row.identifier ?? "") { SourcesViewModel.shared.sources.removeValue(forKey: row); Storage.shared.deleteSource(for: row) }
        for (source, repository) in feeds {
            let identifier = "isign:\(source.id)"
            if let row = Storage.shared.getSources().first(where: { $0.identifier == identifier }) {
                row.name = source.name; row.iconURL = repository.currentIconURL; SourcesViewModel.shared.sources[row] = repository
            } else {
                Storage.shared.addSource(URL(string: "isign-feather://source/\(source.id)")!, repository: repository, id: identifier) { _ in }
                if let row = Storage.shared.getSources().first(where: { $0.identifier == identifier }) { SourcesViewModel.shared.sources[row] = repository }
            }
        }
        Storage.shared.saveContext()
    }
    func removeManagedSources() {
        for row in Storage.shared.getSources() where row.isISignManaged { SourcesViewModel.shared.sources.removeValue(forKey: row); Storage.shared.deleteSource(for: row) }
    }
    func feed(_ source: AltSource) async throws -> ASRepository {
        let client = try requireClient(); let stamp = client.generation
        guard let id = source.identifier?.dropFirst("isign:".count) else { throw ISignFailure(code: "SOURCE_NOT_FOUND") }
        let feed: ISignFeed = try await client.request("sources/\(id)/feed")
        try client.check(stamp)
        guard feed.sourceId == String(id) else { throw ISignFailure(code: "SOURCE_BINDING_MISMATCH") }
        return feed.repository
    }
    func descriptor(_ url: URL) async throws -> ISignDescriptor {
        let reference = try ISignDownloadReference(url)
        let descriptor: ISignDescriptor = try await requireClient().request("sources/\(reference.sourceId)/download", method: "POST", body: ["releaseId": reference.releaseId, "snapshot": reference.snapshot])
        _ = try ISignDownloadPolicy(descriptor.url)
        guard descriptor.headers.isEmpty, descriptor.expiresAt > Date().timeIntervalSince1970 * 1000 else { throw ISignFailure(code: "INVALID_DOWNLOAD_DESCRIPTOR") }
        return descriptor
    }
}
private struct ISignFeed: Decodable { let sourceId: String; let snapshot: String; let repository: ASRepository }

extension AltSource {
    var isISignManaged: Bool { sourceURL?.scheme == "isign-feather" && sourceURL?.host == "source" && identifier?.hasPrefix("isign:") == true }
}
