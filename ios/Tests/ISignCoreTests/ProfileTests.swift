import XCTest
@testable import ISignCore
final class ProfileTests: XCTestCase {
    let bundle = ISignBundle(identityId: "i", connectionId: "c", connectionGeneration: 1, revision: 1, teamId: "NEWTEAM123", certificateSha256: "digest", expiresAt: 9999999999999, p12: "", password: "")
    func profile(_ id: String, team: String = "NEWTEAM123", digest: String = "digest", expiry: Double = 9999999999999) -> ISignProfile { .init(bundleId: id, profile: "", expiresAt: expiry, teamId: team, certificateSha256: digest, deviceIds: ["d"]) }
    func testEveryExtensionRequiresOwnProfileAndCorrectBinding() throws {
        XCTAssertNoThrow(try ISignProfilePolicy.validate([profile("org.app"), profile("org.app.extension")], bundle: bundle, ids: ["org.app", "org.app.extension"], devices: ["d"]))
        for profiles in [[profile("org.app")], [profile("org.app", team: "WRONG")], [profile("org.app", digest: "wrong")], [profile("org.app", expiry: 0)]] {
            XCTAssertThrowsError(try ISignProfilePolicy.validate(profiles, bundle: bundle, ids: ["org.app"], devices: ["d", "other"]))
        }
        XCTAssertThrowsError(try ISignProfilePolicy.validate([profile("app"), profile("org.app")], bundle: bundle, ids: ["app", "org.app"], devices: ["d"]))
    }
    func testEffectiveEntitlementsHonorMergeAndPreserveExplicitCapabilities() {
        let original: [String: Any] = ["keychain-access-groups": ["OLDTEAM123.org.app"], "aps-environment": "production"]
        let plain = ISignProfilePolicy.entitlements(team: "NEWTEAM123", bundleId: "new.app", original: original, merge: false, custom: nil)
        XCTAssertNil(plain["keychain-access-groups"]); XCTAssertNil(plain["aps-environment"])
        let merged = ISignProfilePolicy.entitlements(team: "NEWTEAM123", bundleId: "new.app", original: original, merge: true, custom: nil)
        XCTAssertEqual(merged["keychain-access-groups"] as? [String], ["NEWTEAM123.org.app"])
        XCTAssertEqual(merged["application-identifier"] as? String, "NEWTEAM123.new.app")
        let explicit = ISignProfilePolicy.entitlements(team: "NEWTEAM123", bundleId: "new.app", original: [:], merge: false, custom: original)
        XCTAssertEqual(explicit["aps-environment"] as? String, "production")
        let renamed = ISignProfilePolicy.entitlements(team: "NEWTEAM123", bundleId: "new.app", original: ["application-identifier": "OLDTEAM123.old.app", "keychain-access-groups": ["OLDTEAM123.old.app", "OLDTEAM123.shared"]], merge: true, custom: nil)
        XCTAssertEqual(renamed["keychain-access-groups"] as? [String], ["NEWTEAM123.new.app", "NEWTEAM123.shared"])
    }
    func testDownloadReferenceCarriesVersionAndSnapshot() throws {
        let reference = try ISignDownloadReference(URL(string: "isign-feather://download/source/release?snapshot=v2")!)
        XCTAssertEqual(reference.sourceId, "source"); XCTAssertEqual(reference.releaseId, "release"); XCTAssertEqual(reference.snapshot, "v2")
        XCTAssertThrowsError(try ISignDownloadReference(URL(string: "isign-feather://download/source/release")!))
    }
    func testManagedDownloadFilenameWorksForOpaqueCDNPaths() {
        XCTAssertEqual(ISignDownloadPolicy.packageFilename("download"), "download.ipa")
        XCTAssertEqual(ISignDownloadPolicy.packageFilename("blob.bin"), "blob.bin.ipa")
        XCTAssertEqual(ISignDownloadPolicy.packageFilename("../App.tipa"), "App.tipa")
    }

    func testInterruptedReplacementUsesOnlyMatchingPreviousProfilePair() throws {
        let replacement = ISignBundle(identityId: "new", connectionId: "c", connectionGeneration: 1, revision: 2, teamId: "NEWTEAM123", certificateSha256: "newdigest", expiresAt: 9999999999999, p12: "", password: "")
        let old = bundle
        let pair = ISignProfilePolicy.fallback([old], replacing: replacement, ids: ["org.app"], devices: ["d"]) { candidate in
            candidate.identityId == old.identityId ? [self.profile("org.app")] : nil
        }
        XCTAssertEqual(pair?.0.identityId, old.identityId)
        let otherConnection = ISignBundle(identityId: "new", connectionId: "other", connectionGeneration: 2, revision: 2, teamId: "NEWTEAM123", certificateSha256: "newdigest", expiresAt: 9999999999999, p12: "", password: "")
        XCTAssertNil(ISignProfilePolicy.fallback([old], replacing: otherConnection, ids: ["org.app"], devices: ["d"]) { _ in [self.profile("org.app")] })
        XCTAssertNil(ISignProfilePolicy.fallback([old], replacing: replacement, ids: ["org.app"], devices: ["other"]) { _ in [self.profile("org.app")] })
    }

    func testRenewalStatusIsOptionalAndPreservesReadyIdentity() throws {
        let legacy = try JSONDecoder().decode(ISignIdentity.self, from: Data(#"{"state":"ready","identityId":"current"}"#.utf8))
        XCTAssertNil(legacy.renewal)
        let renewing = try JSONDecoder().decode(ISignIdentity.self, from: Data(#"{"state":"ready","identityId":"current","renewal":{"state":"action_required","reason":"CERTIFICATE_QUOTA","futureField":true}}"#.utf8))
        XCTAssertEqual(renewing.state, "ready"); XCTAssertEqual(renewing.identityId, "current")
        XCTAssertEqual(renewing.renewal?.state, "action_required"); XCTAssertEqual(renewing.renewal?.reason, "CERTIFICATE_QUOTA")
    }

}
