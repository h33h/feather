import Foundation
import CryptoKit

struct ISignPKCE {
    static let redirect = "isign-feather://auth/callback"
    let state: String
    let verifier: String
    init(state: String = UUID().uuidString + UUID().uuidString, verifier: String = UUID().uuidString + UUID().uuidString) { self.state = state; self.verifier = verifier }
    var challenge: String { Data(SHA256.hash(data: Data(verifier.utf8))).base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "") }
    func code(from url: URL, transaction: String) throws -> String {
        guard let parts = URLComponents(url: url, resolvingAgainstBaseURL: false), parts.scheme == "isign-feather", parts.host == "auth", parts.percentEncodedPath == "/callback", parts.port == nil, parts.user == nil, parts.password == nil, parts.fragment == nil else { throw ISignFailure(code: "INVALID_CALLBACK") }
        let items = parts.queryItems ?? []
        func value(_ key: String) -> String? { let matching = items.filter { $0.name == key }; return matching.count == 1 ? matching[0].value : nil }
        guard value("state") == state, value("transactionId") == transaction, let code = value("code"), !code.isEmpty else { throw ISignFailure(code: "INVALID_CALLBACK") }
        return code
    }
}
struct ISignDownloadPolicy {
    let host: String; let port: Int
    static func packageFilename(_ suggested: String) -> String {
        let name = URL(fileURLWithPath: suggested).lastPathComponent
        return ["ipa", "tipa", "zip"].contains(URL(fileURLWithPath: name).pathExtension.lowercased()) ? name : name + ".ipa"
    }
    init(_ url: URL) throws {
        guard url.scheme == "https", let host = url.host, url.user == nil, url.password == nil else { throw ISignFailure(code: "UNSAFE_DOWNLOAD") }
        self.host = host.lowercased(); port = url.port ?? 443
    }
    func allows(_ url: URL) -> Bool { url.scheme == "https" && url.host?.lowercased() == host && (url.port ?? 443) == port && url.user == nil && url.password == nil }
}
struct ISignDownloadReference {
    let sourceId: String; let releaseId: String; let snapshot: String
    init(_ url: URL) throws {
        let paths = url.pathComponents.filter { $0 != "/" }
        let snapshots = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems?.filter { $0.name == "snapshot" } ?? []
        guard url.scheme == "isign-feather", url.host == "download", paths.count == 2, paths.allSatisfy({ !$0.contains("/") && $0 != "." && $0 != ".." }), snapshots.count == 1, let snapshot = snapshots.first?.value, !snapshot.isEmpty else { throw ISignFailure(code: "INVALID_DOWNLOAD_REFERENCE") }
        sourceId = paths[0]; releaseId = paths[1]; self.snapshot = snapshot
    }
}
enum ISignProfilePolicy {
    static func fallback(_ candidates: [ISignBundle], replacing current: ISignBundle, ids: [String], devices: [String], profilesFor: (ISignBundle) -> [ISignProfile]?) -> (ISignBundle, [ISignProfile])? {
        for candidate in candidates.reversed() where candidate.isValid && candidate.connectionId == current.connectionId && candidate.connectionGeneration == current.connectionGeneration && candidate.teamId == current.teamId {
            guard let profiles = profilesFor(candidate), (try? validate(profiles, bundle: candidate, ids: ids, devices: devices)) != nil else { continue }
            return (candidate, profiles)
        }
        return nil
    }
    static func validate(_ profiles: [ISignProfile], bundle: ISignBundle, ids: [String], devices: [String]) throws {
        guard bundle.isValid, profiles.count == ids.count, Set(ids).count == ids.count else { throw ISignFailure(code: "INVALID_SIGNING_BINDING") }
        for id in ids {
            // Zsign chooses the first suffix match. Reject ambiguous IDs before calling it.
            guard !ids.contains(where: { $0 != id && ("\(bundle.teamId).\($0)").hasSuffix(id) }),
                  let profile = profiles.first(where: { $0.bundleId == id }), profile.teamId == bundle.teamId,
                  profile.certificateSha256.lowercased() == bundle.certificateSha256.lowercased(),
                  profile.expiresAt > Date().timeIntervalSince1970 * 1000,
                  Set(devices).isSubset(of: Set(profile.deviceIds)), !devices.isEmpty else { throw ISignFailure(code: "INVALID_SIGNING_BINDING") }
        }
    }
    static func entitlements(team: String, bundleId: String, original: [String: Any], merge: Bool, custom: [String: Any]?) -> [String: Any] {
        var result = custom ?? [:]
        result["application-identifier"] = "\(team).\(bundleId)"
        result["com.apple.developer.team-identifier"] = team
        if custom == nil { result["get-task-allow"] = false }
        if let groups = (custom ?? (merge ? original : [:]))["keychain-access-groups"] as? [String] {
            result["keychain-access-groups"] = groups.compactMap { group -> String? in
                let split = group.split(separator: ".", maxSplits: 1).map(String.init)
                guard split.count == 2, split[0].count == 10 else { return custom == nil ? nil : group }
                let oldApplication = ((custom ?? original)["application-identifier"] as? String)?.split(separator: ".", maxSplits: 1).dropFirst().first.map(String.init)
                let suffix = split[1] == oldApplication ? bundleId : split[1].replacingOccurrences(of: "*", with: bundleId)
                return "\(team).\(suffix)"
            }
        }
        return result
    }
}
