# Contributing to DropSync

Help make sharing between paired devices reliable and easy to understand. Small, focused contributions are welcome. By contributing, you agree to the [Code of Conduct](CODE_OF_CONDUCT.md). Contributions must be compatible with the existing [DropSync Noncommercial License](LICENSE); no additional rights or ownership are implied.

## Before you start

Search existing issues, then open a bug report or feature request for substantial changes. Explain the user problem, affected platform and expected behavior. Report suspected vulnerabilities through [private vulnerability reporting](https://github.com/Taxperia/dropsync/security/advisories/new), not public issues.

Use synthetic filenames and isolated data directories. Never publish pairing codes, private keys, API secrets, account tokens, personal logs or other people's network details.

## Development

Node.js 22.12+ is required. Run `npm ci`, then `npm start` for the local browser service or `npm run desktop` for Electron. The service UI is at `http://127.0.0.1:47821/`.

Use `DROPSYNC_DATA_DIR`, `DROPSYNC_PORT` and `DROPSYNC_DISCOVERY_PORT` to separate development instances. Do not run two processes against one data directory. Windows uses DPAPI. macOS/Linux desktop requires an OS secret store; CLI mode requires `DROPSYNC_VAULT_PASSPHRASE` with at least 12 characters. Keep secrets outside the checkout.

Optional account hosting is separate from file transfer. Copy `auth-server/.env.example` to a private `.env` and review each setting. The account storage key is a persistent server-only secret, separate from the public client key; losing it can make records unreadable. Configure a valid HTTPS reverse proxy before exposing the account service. Business deployments require separate written permission under the license.

## Checks

- `npm run check` parses JavaScript without starting the application.
- Node regression fixtures run on an isolated Docker-capable Linux host: provision `node:22-bookworm-slim`, then run `bash scripts/test-isolated.sh`. The runner disables networking, mounts source read-only, uses an empty target environment, and bounds resources. For release validation, set `DROPSYNC_TEST_IMAGE` to a reviewed image digest.
- Java/Node protocol checks: `npm run test:android-protocol` and `npm run test:android-transfer` need JDK 17+ and Android SDK sources. Run them only in an isolated test environment.
- UI, desktop and Android smoke tests require disposable runners. Android reset smoke tests must use an explicitly selected isolated emulator, never a physical or personal device. Inspect each script before running it.

Describe exactly which checks ran and which remain pending in your pull request. Passing syntax checks does not establish runtime correctness or security.

## Trust boundaries

Device pairing must remain independent of account sign-in. Never automatically open, execute, extract or write clipboard content on behalf of a remote device. Render network-provided labels and filenames as text. Local mutations require same-origin protection and CSRF checks; private files must never enter the static asset allowlist.

Protocol changes must update both Node and the production Java implementation, include negative interoperability cases, and document compatibility. Preserve receiver approval, pinned identities, authenticated completion, cancellation and trust revocation. Ask for focused review when changing pairing, transfer, vaults, account authorization or update metadata.

## Builds and release acceptance

Desktop packages: `npm run dist:win`, `npm run dist:mac`, or `npm run dist:linux` on the corresponding OS. Android uses JDK 17 and the SDK configured in `android/`; run `./gradlew assembleRelease` there.

Android release builds require the existing production keystore and `DROPSYNC_ANDROID_KEYSTORE`, `DROPSYNC_ANDROID_STORE_PASSWORD`, `DROPSYNC_ANDROID_KEY_ALIAS`, and `DROPSYNC_ANDROID_KEY_PASSWORD`. Debug builds intentionally require the original development certificate through `DROPSYNC_DEBUG_KEYSTORE` or `-PdropsyncDebugKeystore=...`. Do not generate a replacement just to make the build pass; a different signer prevents in-place updates.

Before publishing a current release, validate bidirectional Node/Android interoperability, approval/decline/expiry, interrupted transfers, retries without duplicate saves, trust revocation, encrypted vault migration, SAF folder grants, notifications, sleep/process-death behavior, native filesystem publication, and upgrade compatibility on each claimed platform. Complete independent protocol review before making production security claims.

`.github/workflows/package-candidates.yml` creates review artifacts on manual dispatch; it does not publish releases. Android signing is gated by the protected `release-build` environment and `DROPSYNC_ANDROID_RELEASE_READY=true`. Never expose signing or account secrets to untrusted pull-request code.

The update manifest requires a separately protected Ed25519 publisher key. `npm run release:manifest -- artifacts.local.json release-output` signs package metadata; it does not upload files. Configure only the public verification key in `update-config.json`. Do not turn on updates until package provenance, platform signing and the full update path have been validated.

Only the public root README, contribution guide, code of conduct and security policy are included as Markdown in Git. Internal notes, roadmaps and build output stay local. Distribute installers, APKs and fresh SHA-256 checksums through GitHub Releases. Never tag current source as the original source of an older binary; explicitly label archived packages when their original revision is unavailable.
