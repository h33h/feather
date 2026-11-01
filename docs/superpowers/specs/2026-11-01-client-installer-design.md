# Single-release web installer

The web installs one operator-published iSign Client IPA. The iOS application continues to download, modify and sign arbitrary applications locally.

The backend will expose a client-installation submission rather than an arbitrary upload/catalog submission. A request binds the published SHA256 and version to the owner, device and current Apple authority. Installation owns copying the pinned source into private storage and advancing its durable job. Replays, concurrent requests, interrupted transfers and revoked authority retain their existing behavior.

Remove the unused imports/selections schema, import recovery, generic enqueue/cancel entry points and discarded composition objects. Require the actual provisioning callbacks instead of unreachable RPC fallbacks. Keep the signing pipeline, isolated guests, cryptographic verification, expiry, cleanup and access checks.

The existing browser/native HTTP contracts stay unchanged. Existing databases require an explicit operator-run schema contraction before upgrading, because legacy import foreign keys can block source cleanup. The SQL step preserves users, connections, devices, jobs and source files; no destructive database migration runs automatically. The private runner authorization route must reach its authenticated handler.

Approach: specialize the existing installer and job lifecycle in place. A new generic upload abstraction would preserve the unnecessary flexibility; replacing the queue or signing engine would expand scope without simplifying the installer.
