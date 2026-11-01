import XCTest
@testable import ISignCore

@MainActor final class ServiceConfigurationTests: XCTestCase {
    func testEmbeddedOriginInitializesRequestsWithoutUserDefaults() async throws {
        let origin = try ISignServiceConfiguration.server(info: ["ISignServiceOrigin": "https://service.test:8443"])
        let transport = DelayedTransport()
        let client = try ISignClient(server: origin, vault: MemoryVault(), transport: transport)
        let task = Task { try await client.raw("session", authenticated: false) }
        await transport.wait("session")
        let request = await transport.request("session")
        XCTAssertEqual(request?.url?.absoluteString, "https://service.test:8443/api/native/v1/session")
        await transport.respond("session", Data("{}".utf8))
        _ = try await task.value
    }

    func testInvalidOrUnexpandedBuildOriginsAreRejected() {
        for value in ["", "$(ISIGN_SERVICE_ORIGIN)", "https://", "http://service.test", "https://service.test/api", "https://u:p@service.test", "https://service.test?token=1", "https://isign.example.invalid", "https://service.test/#x"] {
            XCTAssertThrowsError(try ISignServiceConfiguration.server(info: ["ISignServiceOrigin": value]), value)
        }
        XCTAssertThrowsError(try ISignServiceConfiguration.server(info: [:]))
    }
}
