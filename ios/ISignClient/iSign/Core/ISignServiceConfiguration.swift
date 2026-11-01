import Foundation

@MainActor enum ISignServiceConfiguration {
    /// The service origin is part of the build, never a user preference or callback parameter.
    static func server(info: [String: Any]) throws -> URL {
        guard let value = info["ISignServiceOrigin"] as? String,
              !value.isEmpty, !value.contains("$("), value == value.trimmingCharacters(in: .whitespacesAndNewlines),
              let url = URL(string: value), let host = url.host, !host.lowercased().hasSuffix(".invalid")
        else { throw ISignFailure(code: "SERVICE_ORIGIN_NOT_CONFIGURED") }
        try ISignClient.validate(url)
        return url
    }
}
