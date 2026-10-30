# Security policy

## Supported versions

| Version | Status |
| --- | --- |
| 0.7.0 source on `main` | Active development; reports are welcome; runtime/platform validation remains pending |
| 0.5.1 legacy preview assets | Archived evaluation builds; do not contain current protocol/security changes; no maintenance commitment |
| Earlier versions | Unsupported |

There is no stable production release. DropSync has not received a comprehensive independent security audit. Source-level protections and passing checks are not security certification.

## Report a vulnerability privately

Use [GitHub private vulnerability reporting](https://github.com/Taxperia/dropsync/security/advisories/new). Include the affected version or commit, platform, trust boundary, expected and actual behavior, and the smallest safe reproduction using synthetic files and identities. Share a proposed fix if you have one.

Do not put private keys, pairing codes, account tokens, personal file contents or other people's network details in public issues. Avoid testing against live systems or devices you do not control. Coordinate disclosure with the maintainer before publishing exploit details. Response time depends on maintainer availability; there is no guaranteed response SLA or paid bounty program.

## Current source security model

- Explicitly paired devices are the authorization boundary. Sharing a Wi-Fi network, appearing in discovery, or signing into the same account does not authorize a transfer. Compare fingerprints through a trusted channel during pairing.
- Transfer v2 uses pinned Ed25519 identities, ephemeral-sender X25519/HKDF-SHA-256 key agreement, AES-256-GCM frames, encrypted filenames/hashes, and authenticated completion receipts. Upgrade both endpoints together; there is no protocol downgrade to 0.5.x.
- Receiving requests require approval by default. Files do not automatically open or execute; clipboard sharing requires an explicit user action and does not collect history or overwrite another device's clipboard.
- Local identity, trust, settings, history and API secrets use an unlocked OS/passphrase vault. Windows uses user-scoped DPAPI; macOS/Linux desktop uses the OS secret store and rejects weak Linux fallback. CLI mode on macOS/Linux requires a strong passphrase. Android uses a non-exportable Keystore wrapping key; hardware backing depends on the device.
- The UI/API binds to loopback. Peer endpoints are intended for private LAN/Tailscale use. Do not port-forward the application to the public internet.
- Update verification requires an embedded publisher Ed25519 public key and checks package hashes and sizes. No publisher key is configured, so updates remain disabled. Platform signing and manifest signing are separate controls.

## Limits and external services

Transfer sizes/timing, IP addresses, device discovery names and public keys can remain visible. The protocol does not provide full forward secrecy against later theft of a recipient's long-term exchange key. Malware with access to the unlocked OS/application account is outside the protection offered by an application vault.

Saved files and outgoing staging copies remain ordinary filesystem files. Node incoming partial files rely on filesystem permissions; Android incoming quarantine uses authenticated encrypted chunks. Use disk encryption and secure backups. Node's no-overwrite publication uses hard links; native NTFS/APFS/ext4 behavior needs validation, and FAT/exFAT destinations are currently unsupported.

Executable-extension blocking is not antivirus scanning and cannot detect every disguised file, macro or archive payload. VirusTotal is opt-in and needs your own API key. Hash lookup discloses a content fingerprint to the provider; uploading unknown file contents requires a separate setting and is limited to 32 MiB. A clean report does not guarantee safety.

Account hosting/OIDC and device pairing are separate trust domains. Real identity-provider, EMM, vault migration, device lifecycle and platform upgrade behavior require independent validation. Revoking trust cannot recall files that a peer already received.
