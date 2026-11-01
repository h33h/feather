import SwiftUI

struct ISignDevicesView: View {
    @ObservedObject private var store = ISignStore.shared
    @Environment(\.scenePhase) private var scenePhase
    @State private var collecting = false
    var body: some View {
        Form {
            Section {
                Button(.localized("Register This Device")) { Task { await store.run {
                    let result: ISignChallenge = try await store.requireClient().request("devices/challenge", method: "POST", body: [:])
                    guard result.profileUrl.scheme == "https" else { throw ISignFailure(code: "INVALID_PROFILE_URL") }
                    collecting = true; await UIApplication.shared.open(result.profileUrl)
                } } }
                Button(.localized("Refresh Devices")) { refresh() }
            } footer: { Text(.localized("Safari downloads a configuration profile. Open Settings to install it, then return here to finish Apple registration. Registration consumes an Apple device slot.")) }
            ForEach(store.devices?.devices ?? []) { device in
                NavigationLink { ISignDeviceDetail(device: device) } label: {
                    VStack(alignment: .leading, spacing: 4) {
                        Label(device.name, systemImage: device.selected ? "checkmark.circle.fill" : "iphone")
                        Text(device.status + (device.os_version.map { " · \($0)" } ?? "")).font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
            if let collected = store.devices?.collectedDevices, !collected.isEmpty {
                Section(.localized("Collected Devices")) {
                    ForEach(collected) { device in
                        DisclosureGroup(device.name) {
                            Text(device.udid).font(.caption.monospaced()).textSelection(.enabled)
                            Text(device.status).foregroundStyle(.secondary)
                            ForEach(device.bindings, id: \.deviceId) { binding in Text("\(binding.teamId) · \(binding.status)").font(.caption) }
                            if let binding = device.bindings.first(where: { $0.connectionId == store.apple?.connection?.id }) {
                                ISignConfirmAction(title: .localized("Register with Apple"), message: .localized("Register this device with Apple? This consumes a device slot that may not be recoverable until your membership renews.")) {
                                    try await store.mutate("devices/\(binding.deviceId)/register", body: ["slotConsent": true], fresh: true); try await store.sync()
                                }
                            } else { Text(.localized("Connect an Apple account and refresh to prepare registration.")).font(.caption).foregroundStyle(.secondary) }
                            ISignConfirmAction(title: .localized("Remove Collected Device"), message: .localized("Remove this device record from iSign?")) {
                                try await store.mutate("devices/collected/\(device.id)/remove"); try await store.sync()
                            }
                        }
                    }
                }
            }
            ISignStatusSection()
        }.navigationTitle(.localized("Devices"))
        .task(id: collecting) {
            guard collecting, let client = store.client else { return }
            let stamp = client.generation
            for _ in 0..<40 {
                try? await Task.sleep(nanoseconds: 3_000_000_000)
                guard !Task.isCancelled, stamp == client.generation else { return }
                do { let devices: ISignDevices = try await client.request("devices"); try client.check(stamp); store.devices = devices } catch { store.error = error.localizedDescription; return }
            }
            collecting = false
        }
        .onChange(of: scenePhase) { phase in if phase == .active { refresh() } }
    }
    private func refresh() { Task { await store.run { try await store.sync() } } }
}
private struct ISignDeviceDetail: View {
    let device: ISignDevices.Device
    @ObservedObject private var store = ISignStore.shared
    @State private var name = ""
    @State private var version = ""
    var body: some View {
        Form {
            Section {
                LabeledContent(.localized("Status"), value: device.status)
                TextField(.localized("Device Name"), text: $name)
                Button(.localized("Save Name")) { action("rename", ["name": name]) }
                TextField(.localized("OS Version"), text: $version).keyboardType(.decimalPad)
                Button(.localized("Save OS Version")) { action("os", ["version": version]) }
                Button(.localized("Use for Signing")) { action("select") }
                Button(.localized("Check Registration")) { action("poll") }
                ISignConfirmAction(title: .localized("Register with Apple"), message: .localized("Registration consumes an Apple device slot. Continue?")) {
                    try await store.mutate("devices/\(device.id)/register", body: ["slotConsent": true], fresh: true); try await store.sync()
                }
                ISignConfirmAction(title: .localized("Remove Device"), message: .localized("Remove this device from iSign? Apple may continue counting its device slot.")) {
                    try await store.mutate("devices/\(device.id)/remove"); try await store.sync()
                }
            }
            ISignStatusSection()
        }.navigationTitle(device.name).onAppear { name = device.name; version = device.os_version ?? "" }
    }
    private func action(_ action: String, _ body: [String: Any] = [:]) { Task { await store.run { try await store.mutate("devices/\(device.id)/\(action)", body: body); try await store.sync() } } }
}
