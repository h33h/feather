import Foundation

struct ISignTokens: Codable, Sendable {
    var accessToken: String
    var refreshToken: String
    var tokenType: String
    var expiresAt: Double
    var refreshExpiresAt: Double
    var sessionId: String
}
struct ISignOwner: Codable, Sendable {
    var ownerId: String
    var role: String
    var loginName: String
    var publicProfileId: String
    var sessionId: String
    var verifiedAt: Double
    var expiresAt: Double
}
struct ISignAuthStart: Decodable { let transactionId: String; let authorizationUrl: URL; let expiresAt: Double }
struct ISignIdentity: Codable {
    struct Renewal: Codable { let state: String; let reason: String? }
    let renewal: Renewal?
    let state: String
    let connectionId: String?
    let connectionGeneration: Int?
    let teamId: String?
    let identityId: String?
    let revision: Int?
    let certificateSha256: String?
    let expiresAt: Double?
    let reason: String?
}
struct ISignBundle: Codable {
    let identityId: String; let connectionId: String; let connectionGeneration: Int
    let revision: Int; let teamId: String; let certificateSha256: String
    let expiresAt: Double; let p12: String; let password: String
    var isValid: Bool { expiresAt > Date().timeIntervalSince1970 * 1000 }
}
struct ISignProfile: Codable {
    let bundleId: String; let profile: String; let expiresAt: Double; let teamId: String
    let certificateSha256: String; let deviceIds: [String]
}
struct ISignProfiles: Codable {
    let operationId: String; let state: String; let profiles: [ISignProfile]; let reason: String?
}
struct ISignDescriptor: Decodable { let url: URL; let headers: [String: String]; let expiresAt: Double }
struct ISignSources: Decodable { let sources: [ISignSource] }
struct ISignSource: Decodable, Identifiable {
    let id: String; let name: String; let state: String; let revision: Int?
    let canonicalUrl: String?; let last_error: String?
}
struct ISignApple: Decodable {
    struct Connection: Decodable { let id: String?; let team_id: String?; let state: String; let shared: Bool; let last_error: String?; let identityReady: Bool? }
    struct Share: Decodable, Identifiable { let id: String; let generation: Int; let state: String; let connectionId: String; let teamId: String; let direction: String; let profileId: String }
    let connection: Connection?; let uploadAllowed: Bool; let shares: [Share]
}
struct ISignDevices: Decodable {
    struct Device: Decodable, Identifiable {
        let id: String; let name: String; let status: String; let os_version: String?; let selected: Bool; let team_id: String?
    }
    struct Collected: Decodable, Identifiable {
        struct Binding: Decodable { let deviceId: String; let connectionId: String; let teamId: String; let generation: Int; let status: String; let shared: Bool }
        let id: String; let name: String; let udid: String; let product: String?; let osVersion: String?; let createdAt: Double; let verifiedAt: Double; let status: String; let bindings: [Binding]
    }
    let devices: [Device]; let collectedDevices: [Collected]
}
struct ISignChallenge: Decodable { let profileXml: String; let profileUrl: URL; let qrSvg: String; let expiresAt: Double }
struct ISignAdminUsers: Decodable {
    struct User: Decodable, Identifiable { let id: String; let loginName: String; let role: String; let status: String }
    let users: [User]
}
struct ISignInvite: Decodable { let token: String; let expiresAt: Double }
struct ISignOK: Decodable { let ok: Bool? }
struct ISignFailure: Error, LocalizedError, Decodable {
    let code: String
    var requestId: String? = nil
    var errorDescription: String? {
        switch code {
        case "HTTPS_ORIGIN_REQUIRED": return "This build has an invalid iSign service address. Install a configured build."
        case "SERVICE_ORIGIN_NOT_CONFIGURED": return "This build has no valid iSign service address. Install a configured build."
        case "SERVICE_UNAVAILABLE": return "iSign could not start. Check the app’s connection error and try again."
        case "STALE_SESSION": return "Your iSign account changed. Please try again."
        case "AUTH_REQUIRED", "UNAUTHORIZED": return "Sign in to iSign again."
        case "UNSUPPORTED_ENTITLEMENT": return "This app requests capabilities the service cannot provision. Review its custom entitlements."
        default: return code.replacingOccurrences(of: "_", with: " ").capitalized + (requestId.map { " (\($0))" } ?? "")
        }
    }
}
