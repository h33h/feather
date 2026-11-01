import XCTest
@testable import AltSourceKit
final class RepositoryTests: XCTestCase {
    func testMissingIconAndUnixSeconds() throws {
        let app = try JSONDecoder().decode(ASRepository.App.self, from: Data(#"{"name":"App","bundleIdentifier":"test.app","date":1700000000}"#.utf8))
        XCTAssertNil(app.iconURL)
        XCTAssertEqual(app.date?.date.timeIntervalSince1970, 1700000000)
    }
    func testScreenshotForms() throws {
        for fixture in [#"["https://a.test/1", "https://a.test/2"]"#, #"[{"url":"https://a.test/1","width":400,"height":800},{"url":"https://a.test/2"}]"#, #"["https://a.test/1",{"url":"https://a.test/2"}]"#] {
            let value = try JSONDecoder().decode(ASRepository.App.Screenshots.self, from: Data(fixture.utf8))
            XCTAssertEqual(value.iPhone?.count, 2); XCTAssertNil(value.iPad)
        }
        let dictionary = try JSONDecoder().decode(ASRepository.App.Screenshots.self, from: Data(#"{"iphone":["https://a.test/phone"],"ipad":[{"url":"https://a.test/pad","width":1024}]}"#.utf8))
        XCTAssertEqual(dictionary.iPhone?.first?.path, "/phone"); XCTAssertEqual(dictionary.iPad?.first?.path, "/pad")
    }
    func testBackendRepositoryScreenshotAliasesAndMixedDeviceArrays() throws {
        let fixture = #"{"name":"Backend catalog","apps":[{"name":"App","bundleIdentifier":"com.example.app","version":"1.0","downloadURL":"isign-feather://download/source/release?snapshot=one","screenshots":{"iphone":[{"imageURL":"https://cdn.example/screen.png","width":500,"height":1000},"https://cdn.example/phone-string.png",{"url":"https://cdn.example/phone-url.png"}],"ipad":["https://cdn.example/pad-string.png",{"url":"https://cdn.example/pad-url.png","width":1024},{"imageURL":"https://cdn.example/pad-image.png","height":1366}]}}]}"#
        let repository = try JSONDecoder().decode(ASRepository.self, from: Data(fixture.utf8))
        XCTAssertEqual(repository.apps.count, 1)
        XCTAssertEqual(repository.apps[0].screenshots?.iPhone?.map(\.lastPathComponent), ["screen.png", "phone-string.png", "phone-url.png"])
        XCTAssertEqual(repository.apps[0].screenshots?.iPad?.map(\.lastPathComponent), ["pad-string.png", "pad-url.png", "pad-image.png"])
    }

}
