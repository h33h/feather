# Single-release client installer implementation plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Remove arbitrary server-upload/import paths while preserving installation of the operator-published client.

**Architecture:** ClientInstallations owns source reception; JobLifecycle accepts a pinned client release and device. Keep storage, provisioning and isolated signing boundaries.

**Tech Stack:** TypeScript, Next.js, PostgreSQL, Vitest/PGlite; Python runner.

**Spec:** docs/superpowers/specs/2026-11-01-client-installer-design.md

## Global constraints

- Preserve browser/native HTTP contracts and arbitrary IPA signing in iOS.
- Preserve idempotency, source digest checks, owner/device authority, leases, retry and cleanup.
- No automatic destructive migration of existing databases.

## Review focus

- Reusing a key with a different release or device must fail.
- A source transfer or queue completion failure must leave a stable terminal operation.
- Concurrent requests and worker restarts must not duplicate work.
- Revoked/shared authority must fence source writes and installation tickets.
- The private runner authorizer remains authenticated and reachable.

## Task 1: Specialize client reception and queue submission

- [x] Add regression coverage for release-bound submissions and private runner routing; run it before implementation.
- [x] Add beginClientInstallation(owner, {key, deviceId, releaseSha256, version?}); replace generic enqueue/beginSubmission uses in production and fixtures.
- [x] Move receipt orchestration into ClientInstallations; remove ReceiveUpload and RequestAuthorization.
- [x] Migrate useful generic queue tests to the current client submission path, preserving authority and failure assertions.
- [x] Run client installation, queue, storage and access tests.

## Task 2: Remove obsolete import state and composition paths

- [x] Remove imports/selections DDL, import recovery and obsolete upload option fields; adjust affected cleanup fixtures.
- [x] Provide and test an explicit operator-run upgrade that removes legacy foreign keys without removing current accounts, devices or jobs.
- [x] Remove discarded kernel tickets/diagnostics and pipeline bootstrap/fallbacks; keep the sealed bootstrap path.
- [x] Run lifecycle, startup, composition and architecture tests plus TypeScript checking.

## Task 3: Verify the complete change

- [x] Run the full Vitest suite, typecheck, lint, formatting and production build.
- [x] Run PostgreSQL and browser checks if their local prerequisites are available.
- [x] Review the full diff for source-digest binding, revocation, replay and unchanged iOS scope.
- [x] Update README with the single-release internal model and report actual verification results.

## Verification results

- Full Vitest/PGlite run: 104 files, 667 tests passed.
- Browser run with Chrome: 64 tests passed.
- Production build, TypeScript checking, ESLint and Prettier checks passed.
- Independent review found the legacy imports foreign key issue; the explicit SQL upgrade now has a regression test that reproduces the constraint failure, applies the upgrade and verifies preserved account/device/job data and successful cleanup.
- Integration tests against a standalone PostgreSQL server were unavailable: no local server is configured and Docker daemon is stopped. No existing database was modified.
