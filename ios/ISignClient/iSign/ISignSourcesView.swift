import SwiftUI

struct ISignSourcesView: View {
    @ObservedObject private var store = ISignStore.shared
    @State private var name = ""
    @State private var url = ""
    @State private var trusted = false
    var body: some View {
        Form {
            Section {
                TextField(.localized("Name"), text: $name)
                TextField(.localized("Source URL"), text: $url).textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
                Toggle(.localized("I trust this publisher"), isOn: $trusted)
                Button(.localized("Add Managed Source")) { Task { await store.run {
                    try await store.mutate("sources", body: ["name": name, "url": url, "trustPublisher": true]); name = ""; url = ""; trusted = false; try await store.sync()
                } } }.disabled(!trusted || url.isEmpty || name.isEmpty)
            } footer: { Text(.localized("iSign checks this feed and resolves downloads. The publisher controls its apps. Source URL query parameters are preserved.")) }
            Section(.localized("Managed Sources")) {
                ForEach(store.sources) { source in NavigationLink { ISignSourceDetail(source: source) } label: {
                    VStack(alignment: .leading) { Text(source.name); Text(source.state).font(.caption).foregroundStyle(.secondary) }
                } }
            }
            Section {
                ForEach(Storage.shared.getSources().filter { !$0.isISignManaged }) { source in
                    if let sourceURL = source.sourceURL {
                        ISignConfirmAction(title: .localized("Import") + " “\(source.name ?? sourceURL.host ?? "Source")”", message: .localized("Import this source into iSign and trust its publisher? The local source remains independent.")) {
                            try await store.mutate("sources", body: ["name": source.name ?? "Source", "url": sourceURL.absoluteString, "trustPublisher": true]); try await store.sync()
                        }
                    }
                }
            } header: { Text(.localized("Import Local Sources")) } footer: { Text(.localized("Local sources are never uploaded automatically. Choose each source you want iSign to manage.")) }
            ISignStatusSection()
        }.navigationTitle(.localized("Managed Sources"))
    }
}
private struct ISignSourceDetail: View {
    let source: ISignSource
    @ObservedObject private var store = ISignStore.shared
    @State private var name = ""
    var body: some View {
        Form {
            Section {
                LabeledContent(.localized("State"), value: source.state)
                if let url = source.canonicalUrl { Text(url).font(.caption).textSelection(.enabled) }
                TextField(.localized("Name"), text: $name)
                Button(.localized("Rename")) { action("rename", ["name": name]) }
                Button(.localized("Refresh")) { action("refresh") }
                Button(.localized("Disable")) { action("disable") }
                ISignConfirmAction(title: .localized("Remove Source"), message: .localized("Remove this managed source? Apps in your local library stay on this device.")) {
                    try await store.mutate("sources/\(source.id)/remove"); try await store.sync()
                }
            }
            ISignStatusSection()
        }.navigationTitle(source.name).onAppear { name = source.name }
    }
    private func action(_ action: String, _ body: [String: Any] = [:]) { Task { await store.run { try await store.mutate("sources/\(source.id)/\(action)", body: body); try await store.sync() } } }
}
struct ISignAdminView: View {
    @ObservedObject private var store = ISignStore.shared
    @State private var users: [ISignAdminUsers.User] = []
    @State private var name = ""
    @State private var invitation = ""
    var body: some View {
        Form {
            if store.owner?.role == "admin" {
                Section {
                    TextField(.localized("Invitee Name"), text: $name)
                    Button(.localized("Create Invitation")) { invite("admin/invites", ["name": name]) }.disabled(name.isEmpty)
                    if !invitation.isEmpty { Text(invitation).textSelection(.enabled); Button(.localized("Copy Invitation")) { UIPasteboard.general.string = invitation } }
                }
                ForEach(users) { user in
                    Section {
                        LabeledContent(user.loginName, value: user.role + " · " + user.status)
                        Button(.localized("Reinvite")) { invite("admin/users/\(user.id)/reinvite") }
                        ISignConfirmAction(title: user.status == "blocked" ? .localized("Unblock User") : .localized("Block User"), message: .localized("Change access for this user?")) {
                            try await store.mutate("admin/users/\(user.id)/\(user.status == "blocked" ? "unblock" : "block")", fresh: true); try await reload()
                        }
                        ISignConfirmAction(title: .localized("Delete User"), message: .localized("Permanently delete this user and their service data?")) {
                            try await store.mutate("admin/users/\(user.id)", fresh: true, method: "DELETE"); try await reload()
                        }
                    }
                }
            }
            ISignStatusSection()
        }.navigationTitle(.localized("Administration"))
        .task { await store.run { try await reload() } }
        .onDisappear { invitation = "" }
    }
    private func reload() async throws { guard store.owner?.role == "admin" else { return }; let response: ISignAdminUsers = try await store.requireClient().request("admin/users"); users = response.users }
    private func invite(_ path: String, _ body: [String: Any] = [:]) { Task { await store.run {
        try await store.fresh(); let result: ISignInvite = try await store.requireClient().request(path, method: "POST", body: body); invitation = result.token; try await reload()
    } } }
}
