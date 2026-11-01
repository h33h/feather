import SwiftUI
import UniformTypeIdentifiers
import NimbleViews

struct ISignSettingsView: View {
    @ObservedObject private var store = ISignStore.shared
    @State private var deleting = false
    var body: some View {
        Form {
            if let owner = store.owner {
                Section {
                    LabeledContent(.localized("Account"), value: owner.loginName)
                    LabeledContent(.localized("Role"), value: owner.role)
                    LabeledContent(.localized("Public Profile ID")) { Text(owner.publicProfileId).textSelection(.enabled) }
                    Button(.localized("Verify Account")) { Task { await store.run { try await store.authenticate(stepUp: true) } } }
                    Button(.localized("Sync Now")) { Task { await store.run { try await store.sync() } } }
                    Label(store.status, systemImage: "arrow.triangle.2.circlepath").foregroundStyle(.secondary)
                } header: { Text(.localized("Account")) }
                Section {
                    NavigationLink { ISignAppleView() } label: { Label(.localized("Apple Account & Sharing"), systemImage: "person.crop.circle.badge.checkmark") }
                    NavigationLink { ISignSigningView() } label: { Label(.localized("Managed Signing"), systemImage: "checkmark.seal") }
                    NavigationLink { ISignDevicesView() } label: { Label(.localized("Devices"), systemImage: "iphone") }
                    NavigationLink { ISignSourcesView() } label: { Label(.localized("Managed Sources"), systemImage: "globe") }
                    if owner.role == "admin" { NavigationLink { ISignAdminView() } label: { Label(.localized("Administration"), systemImage: "person.2.badge.gearshape") } }
                }
                Section {
                    Button(.localized("Sign Out"), role: .destructive) { Task { await store.logout() } }
                    Button(.localized("Delete Account"), role: .destructive) { deleting = true }
                }
            } else {
                Section {
                    Button(.localized("Sign In or Accept Invitation")) { Task { await store.run { try await store.authenticate(); try await store.sync() } } }.disabled(store.client == nil || store.busy)
                } footer: { Text(.localized("Continue securely in your browser using your passkey. Your server also handles invitation registration.")) }
            }
            ISignStatusSection()
        }
        .navigationTitle(.localized("iSign"))
        .confirmationDialog(.localized("Delete your iSign account and its service data?"), isPresented: $deleting, titleVisibility: .visible) {
            Button(.localized("Delete Account"), role: .destructive) { Task { await store.run { try await store.mutate("account/delete", fresh: true); await store.logout() } } }
        }
    }
}
struct ISignStatusSection: View {
    @ObservedObject private var store = ISignStore.shared
    var body: some View {
        if store.busy { Section { ProgressView().accessibilityLabel(.localized("Connecting to iSign")) } }
        if let error = store.error { Section { Label(error, systemImage: "exclamationmark.triangle").foregroundStyle(.red).textSelection(.enabled) } }
    }
}
struct ISignAppleView: View {
    @ObservedObject private var store = ISignStore.shared
    @State private var issuer = ""
    @State private var keyId = ""
    @State private var profileId = ""
    @State private var filename = ""
    @State private var p8 = ""
    @State private var picking = false
    @State private var disconnect = false
    var body: some View {
        Form {
            if let connection = store.apple?.connection {
                Section {
                    LabeledContent(.localized("Team"), value: connection.team_id ?? .localized("Pending"))
                    LabeledContent(.localized("Status"), value: connection.state)
                    LabeledContent(.localized("Access"), value: connection.shared ? String.localized("Shared") : String.localized("Owner"))
                    if let reason = connection.last_error { Text(reason).foregroundStyle(.red) }
                    if !connection.shared { Button(.localized("Prepare Apple Account")) { action { try await store.mutate("apple/bootstrap", fresh: true) } } }
                    Button(.localized("Disconnect"), role: .destructive) { disconnect = true }
                }
            }
            if store.apple?.uploadAllowed != false {
                Section {
                    TextField(.localized("Issuer ID"), text: $issuer).textInputAutocapitalization(.never).autocorrectionDisabled()
                    TextField(.localized("Key ID"), text: $keyId).textInputAutocapitalization(.characters).autocorrectionDisabled()
                    Button(filename.isEmpty ? .localized("Choose P8 Key") : filename) { picking = true }
                    Button(.localized("Connect Apple Account")) {
                        action {
                            try await store.mutate("apple/connect", body: ["filename": filename, "issuerId": issuer, "keyId": keyId, "keyType": "team", "p8": p8], fresh: true)
                            p8 = ""; filename = ""; issuer = ""; keyId = ""
                        }
                    }.disabled(p8.isEmpty || issuer.isEmpty || keyId.isEmpty)
                } header: { Text(.localized("App Store Connect API Key")) } footer: { Text(.localized("The selected key is sent to your iSign server. Its original file stays in Files and iSign Client does not keep a copy.")) }
            }
            if store.apple?.connection?.shared == false {
                Section {
                    TextField(.localized("Recipient Public Profile ID"), text: $profileId).textInputAutocapitalization(.never).autocorrectionDisabled()
                    Button(.localized("Share Connection")) { action { try await store.mutate("apple/shares", body: ["publicProfileId": profileId], fresh: true); profileId = "" } }.disabled(profileId.isEmpty)
                } header: { Text(.localized("Share Signing Access")) } footer: { Text(.localized("Recipients can download and export a client certificate. Your P8 and server signing key remain private. Removing access stops future sync; cached certificates remain usable until expiry or revocation. Revoking the common client certificate affects apps signed by every recipient.")) }
            }
            ForEach(store.apple?.shares ?? []) { share in
                Section {
                    LabeledContent(share.profileId, value: share.state)
                    LabeledContent(.localized("Direction"), value: share.direction)
                    if store.apple?.connection?.shared == false && share.state == "active" {
                        ISignConfirmAction(title: .localized("Revoke Share"), message: .localized("Stop future access? Previously downloaded certificates remain usable until expiry or certificate revocation.")) {
                            try await store.mutate("apple/shares/\(share.id)/revoke", fresh: true); try await store.sync()
                        }
                    }
                }
            }
            ISignStatusSection()
        }.navigationTitle(.localized("Apple Account"))
        .fileImporter(isPresented: $picking, allowedContentTypes: [.data]) { result in
            do {
                let url = try result.get(); let scoped = url.startAccessingSecurityScopedResource(); defer { if scoped { url.stopAccessingSecurityScopedResource() } }
                let data = try Data(contentsOf: url)
                guard data.count < 65536, let value = String(data: data, encoding: .utf8), value.contains("PRIVATE KEY") else { throw ISignFailure(code: "INVALID_P8") }
                filename = url.lastPathComponent; p8 = value
            } catch { store.error = error.localizedDescription }
        }
        .onDisappear { p8 = ""; filename = "" }
        .confirmationDialog(.localized("Disconnect Apple signing access?"), isPresented: $disconnect, titleVisibility: .visible) {
            Button(.localized("Disconnect"), role: .destructive) { action { try await store.mutate("apple/disconnect", fresh: true) } }
        }
    }
    private func action(_ work: @escaping @MainActor () async throws -> Void) { Task { await store.run { try await work(); try await store.sync() } } }
}
struct ISignConfirmAction: View {
    let title: String; let message: String; let action: @MainActor () async throws -> Void
    @State private var confirming = false
    var body: some View {
        Button(title, role: .destructive) { confirming = true }
            .confirmationDialog(message, isPresented: $confirming, titleVisibility: .visible) {
                Button(title, role: .destructive) { Task { await ISignStore.shared.run(action) } }
            }
    }
}
struct ISignSigningView: View {
    @ObservedObject private var store = ISignStore.shared
    @State private var exporting = false
    @State private var exportConfirmation = false
    @State private var exportData = ISignCertificateDocument(data: Data())
    @State private var password = ""
    var body: some View {
        Form {
            Section {
                LabeledContent(.localized("Certificate"), value: store.identity?.state ?? .localized("Not synchronized"))
                if let team = store.identity?.teamId { LabeledContent(.localized("Team"), value: team) }
                if let expiry = store.identity?.expiresAt { LabeledContent(.localized("Expires")) { Text(Date(timeIntervalSince1970: expiry / 1000), style: .date) } }
                Label(store.cachedIdentity ? .localized("Available for offline signing") : .localized("No valid cached certificate"), systemImage: store.cachedIdentity ? "checkmark.shield" : "exclamationmark.shield")
                if let reason = store.identity?.reason { Text(reason).foregroundStyle(.red) }
                if let renewal = store.identity?.renewal {
                    Label(renewal.state == "reconciling" ? String.localized("Certificate update in progress") : String.localized("Certificate update needs attention"), systemImage: renewal.state == "reconciling" ? "arrow.triangle.2.circlepath" : "exclamationmark.triangle")
                        .foregroundStyle(.secondary)
                    if let reason = renewal.reason { Text(reason.replacingOccurrences(of: "_", with: " ").capitalized).font(.footnote) }
                    Text(.localized("Your current valid certificate remains available while its replacement is prepared.")).font(.footnote).foregroundStyle(.secondary)
                    if renewal.state == "action_required" && store.apple?.connection?.shared == true { Text(.localized("The connection owner needs to retry this update.")).font(.footnote) }
                }
                Button(.localized("Sync Certificate")) { Task { await store.run { try await store.syncBundle(); try await store.sync() } } }
            } footer: { Text(.localized("Offline signing needs an unexpired certificate and cached profiles matching every app, extension, device, and entitlement. Service errors do not erase valid offline material.")) }
            if store.apple?.connection?.shared == false {
                Section {
                    Button(.localized("Retry Identity Preparation")) { Task { await store.run {
                        try await store.mutate("signing/identity/ensure", body: ["retry": true], fresh: true); try await store.sync()
                    } } }
                    ISignConfirmAction(title: .localized("Revoke Client Certificate"), message: .localized("This revokes the common client certificate for everyone sharing this Apple connection. Apps signed with it may stop working.")) {
                        try await store.mutate("signing/identity/revoke", fresh: true); try await store.sync()
                    }
                }
            }
            if let operation = store.profileOperation {
                Section {
                    Text(.localized("A profile request needs attention. Resolve device, quota, or capability issues before retrying."))
                    Button(.localized("Check Profile Request")) { Task { await store.run {
                        let result: ISignProfiles = try await store.requireClient().request("signing/profiles/\(operation)")
                        store.status = result.reason ?? result.state
                    } } }
                    Button(.localized("Retry Profile Request")) { Task { await store.run { try await store.retryProfiles() } } }
                }
            }
            if store.cachedIdentity {
                Section {
                    Button(.localized("Export Certificate")) { exportConfirmation = true }
                    if !password.isEmpty { SecureField(.localized("Export Password"), text: .constant(password)); Button(.localized("Copy Export Password")) { UIPasteboard.general.string = password } }
                } footer: { Text(.localized("An exported P12 and its password allow signing outside iSign Client. Share them only with someone you trust.")) }
            }
            ISignStatusSection()
        }.navigationTitle(.localized("Managed Signing"))
        .confirmationDialog(.localized("Export this private signing certificate?"), isPresented: $exportConfirmation, titleVisibility: .visible) {
            Button(.localized("Export P12")) {
                do { guard let bundle = try store.cachedBundle(), let data = Data(base64Encoded: bundle.p12) else { return }; exportData = .init(data: data); password = bundle.password; exporting = true } catch { store.error = error.localizedDescription }
            }
        }
        .fileExporter(isPresented: $exporting, document: exportData, contentType: .data, defaultFilename: "iSign-client.p12") { result in
            if case .failure(let error) = result { store.error = error.localizedDescription }
            exportData = .init(data: Data())
        }.onDisappear { password = ""; exportData = .init(data: Data()) }
    }
}
struct ISignCertificateDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.data] }
    var data: Data
    init(data: Data) { self.data = data }
    init(configuration: ReadConfiguration) throws { data = configuration.file.regularFileContents ?? Data() }
    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper { FileWrapper(regularFileWithContents: data) }
}
