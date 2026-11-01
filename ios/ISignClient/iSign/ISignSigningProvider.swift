import Foundation
import CryptoKit

struct ISignSigningTarget {
    let url: URL
    let id: String
    let entitlements: [String: Any]
}
@MainActor extension ISignStore {
    func retryProfiles() async throws {
        let client = try requireClient(); let scope = client.signingScope
        try await fresh()
        try client.checkSigning(scope)
        guard let data = try client.cached("profile-request"), var body = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw ISignFailure(code: "NO_PROFILE_REQUEST") }
        body["retry"] = true
        let result: ISignProfiles = try await client.request("signing/profiles/ensure", method: "POST", body: body)
        try client.checkSigning(scope)
        profileOperation = result.operationId; status = result.reason ?? result.state
    }
    func signManaged(app: URL, options: Options) async throws {
        let client = try requireClient(); let scope = client.signingScope
        // Only network errors permit offline fallback; known revocation clears managed state.
        do {
            let current: ISignIdentity = try await client.request("signing/identity")
            try client.checkSigning(scope); identity = current
            guard current.state == "ready" else {
                try client.observeIdentity(current)
                throw ISignFailure(code: current.reason ?? "IDENTITY_\(current.state.uppercased())")
            }
            if let cached = try? cachedBundle(), cached.identityId == current.identityId, cached.revision == current.revision, cached.connectionGeneration == current.connectionGeneration {} else { try await syncBundle() }
        } catch let error as URLError where [.notConnectedToInternet, .networkConnectionLost, .timedOut, .cannotConnectToHost, .cannotFindHost, .dnsLookupFailed].contains(error.code) {
            status = .localized("Offline — using valid cached signing material")
        }
        try client.checkSigning(scope)
        guard var bundle = try cachedBundle() else { throw ISignFailure(code: "NO_VALID_CACHED_CERTIFICATE") }
        try Self.validateP12(bundle)
        let targets = try signingTargets(app: app, options: options, team: bundle.teamId)
        guard let deviceData = try client.cached("selected-devices") else { throw ISignFailure(code: "SELECT_DEVICE_FIRST") }
        let devices = try JSONDecoder().decode([String].self, from: deviceData)
        guard !devices.isEmpty else { throw ISignFailure(code: "SELECT_DEVICE_FIRST") }
        let body: [String: Any] = ["deviceIds": devices.sorted(), "bundles": targets.map { ["bundleId": $0.id, "entitlements": $0.entitlements] }]
        let requestData = try JSONSerialization.data(withJSONObject: body, options: [.sortedKeys])
        let requestHash = SHA256.hash(data: requestData).map { String(format: "%02x", $0) }.joined()
        func profileCacheKey(_ identity: ISignBundle) -> String { "profiles:\(identity.identityId):\(identity.revision):" + requestHash }
        let cacheKey = profileCacheKey(bundle)
        try client.cacheSigning(requestData, key: "profile-request", scope: scope)
        let profiles: [ISignProfile]
        do {
            var result: ISignProfiles = try await client.request("signing/profiles/ensure", method: "POST", body: body)
            profileOperation = result.operationId
            for _ in 0..<40 where result.state == "reconciling" {
                try await Task.sleep(nanoseconds: 1_500_000_000); try client.checkSigning(scope)
                result = try await client.request("signing/profiles/\(result.operationId)")
            }
            guard result.state == "ready" else { throw ISignFailure(code: result.reason ?? "PROFILE_\(result.state.uppercased())") }
            try ISignProfilePolicy.validate(result.profiles, bundle: bundle, ids: targets.map(\.id), devices: devices)
            try client.cacheSigning(JSONEncoder().encode(result), key: cacheKey, scope: scope)
            profiles = result.profiles; profileOperation = nil
        } catch let error as URLError where [.notConnectedToInternet, .networkConnectionLost, .timedOut, .cannotConnectToHost, .cannotFindHost, .dnsLookupFailed].contains(error.code) {
            try client.checkSigning(scope)
            let history = (try? client.cached("bundle-history").map { try JSONDecoder().decode([ISignBundle].self, from: $0) }) ?? []
            let candidates = history + [bundle]
            guard let pair = ISignProfilePolicy.fallback(candidates, replacing: bundle, ids: targets.map(\.id), devices: devices, profilesFor: { candidate in
                guard let cached = try? client.cached(profileCacheKey(candidate)), let result = try? JSONDecoder().decode(ISignProfiles.self, from: cached), result.state == "ready" else { return nil }
                return result.profiles
            }) else { throw ISignFailure(code: "NO_MATCHING_OFFLINE_PROFILES") }
            bundle = pair.0; profiles = pair.1
            try Self.validateP12(bundle)
            status = .localized("Offline — using a complete cached certificate and profile set")
        }
        try client.checkSigning(scope)
        try ISignProfilePolicy.validate(profiles, bundle: bundle, ids: targets.map(\.id), devices: devices)
        guard let vault, let p12 = Data(base64Encoded: bundle.p12) else { throw ISignFailure(code: "INVALID_SIGNING_BUNDLE") }
        let stage = try vault.stage(); defer { try? FileManager.default.removeItem(at: stage) }
        var assets: [[String: String]] = []
        for (index, target) in targets.enumerated() {
            guard let profile = profiles.first(where: { $0.bundleId == target.id }), let cms = Data(base64Encoded: profile.profile) else { throw ISignFailure(code: "MISSING_PROFILE") }
            try validateCMS(cms, bundle: bundle, target: target)
            let provision = stage.appendingPathComponent("\(index).mobileprovision"), entitlements = stage.appendingPathComponent("\(index).plist")
            try cms.write(to: provision, options: .completeFileProtection)
            try PropertyListSerialization.data(fromPropertyList: target.entitlements, format: .xml, options: 0).write(to: entitlements, options: .completeFileProtection)
            assets.append(["profile": provision.path, "entitlements": entitlements.path, "team": bundle.teamId, "bundleId": target.id])
        }
        try client.checkSigning(scope)
        // Never block the UI during Mach-O signing. Logout may delete staging; that
        // fails closed, and the generation check rejects any already-running result.
        let signingAssets = assets
        let signed = await Task.detached { ISignSignBundles(app.path, p12, bundle.password, signingAssets) }.value
        try client.checkSigning(scope)
        guard signed else { throw SigningFileHandlerError.signFailed }
        for target in targets {
            let embedded = target.url.appendingPathComponent("embedded.mobileprovision")
            let expected = profiles.first(where: { $0.bundleId == target.id })!
            guard try Data(contentsOf: embedded) == Data(base64Encoded: expected.profile) else { throw ISignFailure(code: "SIGNED_PROFILE_MISMATCH") }
            if options.removeProvisioning { try FileManager.default.removeItem(at: embedded) }
        }
        try client.checkSigning(scope)
    }
    private func signingTargets(app: URL, options: Options, team: String) throws -> [ISignSigningTarget] {
        var urls = [app]
        var unprovisionedBundleIDs: [String] = []
        if let enumerator = FileManager.default.enumerator(at: app, includingPropertiesForKeys: [.isSymbolicLinkKey]) {
            for case let url as URL in enumerator {
                if ["app", "appex"].contains(url.pathExtension) {
                    guard try url.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink != true else { throw ISignFailure(code: "UNSUPPORTED_BUNDLE_SYMLINK") }
                    urls.append(url)
                } else if ["framework", "xctest"].contains(url.pathExtension), let info = NSDictionary(contentsOf: url.appendingPathComponent("Info.plist")), let id = info["CFBundleIdentifier"] as? String {
                    unprovisionedBundleIDs.append(id)
                }
            }
        }
        let custom: [String: Any]?
        if let file = options.appEntitlementsFile {
            let scoped = file.startAccessingSecurityScopedResource(); defer { if scoped { file.stopAccessingSecurityScopedResource() } }
            guard let dictionary = try PropertyListSerialization.propertyList(from: Data(contentsOf: file), format: nil) as? [String: Any] else { throw ISignFailure(code: "INVALID_CUSTOM_ENTITLEMENTS") }
            custom = dictionary
        } else { custom = nil }
        return try urls.map { url in
            guard let info = NSDictionary(contentsOf: url.appendingPathComponent("Info.plist")), let id = info["CFBundleIdentifier"] as? String, !id.isEmpty, let exec = info["CFBundleExecutable"] as? String else { throw ISignFailure(code: "INVALID_APP_BUNDLE") }
            guard !unprovisionedBundleIDs.contains(where: { (team + "." + id).hasSuffix($0) }) else { throw ISignFailure(code: "AMBIGUOUS_PROFILE_SELECTOR") }
            var original: [String: Any] = [:]
            if options.mergeEntitlements, let data = LCGetMachOEntitlements(url.appendingPathComponent(exec).path) { original = (try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any]) ?? [:] }
            let desired = ISignProfilePolicy.entitlements(team: team, bundleId: id, original: original, merge: options.mergeEntitlements, custom: custom)
            return .init(url: url, id: id, entitlements: desired)
        }
    }
    private func validateCMS(_ cms: Data, bundle: ISignBundle, target: ISignSigningTarget) throws {
        guard let content = ISignCMSContent(cms),
              let profile = try PropertyListSerialization.propertyList(from: content, format: nil) as? [String: Any],
              let teams = profile["TeamIdentifier"] as? [String], teams == [bundle.teamId],
              let expiry = profile["ExpirationDate"] as? Date, expiry > Date(),
              let certificates = profile["DeveloperCertificates"] as? [Data],
              certificates.contains(where: { SHA256.hash(data: $0).map { String(format: "%02x", $0) }.joined() == bundle.certificateSha256.lowercased() }),
              let entitlements = profile["Entitlements"] as? [String: Any], let application = entitlements["application-identifier"] as? String
        else { throw ISignFailure(code: "PROFILE_CONTENT_MISMATCH") }
        let expected = "\(bundle.teamId).\(target.id)"
        guard application == expected || (application.hasSuffix(".*") && expected.hasPrefix(String(application.dropLast()))) else { throw ISignFailure(code: "PROFILE_APPLICATION_MISMATCH") }
        // Verify the requested entitlements are within the authenticated CMS ceiling.
        for (key, requested) in target.entitlements {
            guard let allowed = entitlements[key], Self.entitlement(allowed, permits: requested) else { throw ISignFailure(code: "PROFILE_ENTITLEMENT_MISMATCH") }
        }
    }
    private static func entitlement(_ allowed: Any, permits requested: Any) -> Bool {
        if let value = requested as? String, let ceiling = allowed as? String { return ceiling == value || (ceiling.hasSuffix("*" ) && value.hasPrefix(String(ceiling.dropLast()))) }
        if let values = requested as? [String], let ceiling = allowed as? [String] { return values.allSatisfy { value in ceiling.contains { entitlement($0, permits: value) } } }
        return NSDictionary(dictionary: ["value": allowed]).isEqual(to: ["value": requested])
    }
}
