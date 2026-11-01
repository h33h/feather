import SwiftUI

/// A managed identity is deliberately separate from the manual CertificatePair rows.
struct ISignManagedCertificateLabel: View {
    @ObservedObject private var store = ISignStore.shared
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Label(.localized("iSign Managed Certificate"), systemImage: "checkmark.seal")
            if let team = store.identity?.teamId {
                Text(team).font(.subheadline).foregroundStyle(.secondary)
            }
            Text(store.cachedIdentity ? String.localized("Valid certificate cached on this device") : store.status)
                .font(.footnote).foregroundStyle(.secondary)
            if let identity = store.identity, identity.state != "ready" {
                Text(identity.state.replacingOccurrences(of: "_", with: " ").capitalized)
                    .font(.footnote).foregroundStyle(.secondary)
            }
        }
    }
}
