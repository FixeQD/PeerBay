PeerBay connects Android, Linux, and Windows devices over local connections. This document describes how it handles trust, pairing, data transfers, permissions, and privileged operations, along with the threats it protects against and the ones it cannot fully handle.

## Rules

PeerBay works locally without user accounts, mandatory cloud services, or operator controlled relay servers. Devices trust each other through locally stored identities and user approved pairing.

A device is trusted only when:

1. It has an identity key and a transport certificate.
2. The user has completed pairing.
3. Its certificate fingerprint matches the stored trust record.
4. The current session policy allows the requested feature.

Being on the same network, presenting a self signed certificate, or having an active ADB connection does not make a device trusted.

## Device identity and pairing

Each peer stores its own device ID, identity key, transport certificate, certificate fingerprint, protocol versions, capabilities, trust record, and feature policies.

Private keys never leave their device. They are not exposed through the UI or protocol messages. PeerBay uses secure storage when available, otherwise it stores secrets in a locally encrypted storage area.

Discovery only finds potential peers. Discovery responses never contain secrets or pairing tokens.

Normal pairing works like this:

```
pair.start
  -> exchange nonces
  -> reveal nonces
  -> calculate an SAS code from the fingerprints and nonces
  -> compare the code on both devices
  -> user approves
  -> save the trust record
  -> exchange session tokens
```

Pairing fails if the codes do not match. On timeout, cancellation, or rejection, PeerBay removes temporary nonces, tokens, and incomplete trust records.

USB ADB can simplify connection setup, but it does not replace PeerBay pairing. Approving Android's USB debugging prompt does not grant access to every PeerBay feature.

Users can remove trusted peers and revoke permissions at any time. This includes ADB, Accessibility, MediaProjection, Shizuku, and root access on Android. Revoking access stops the affected channels and workers.

## Protocol and replay protection

Control messages use a versioned envelope:

```
v
id
t
sid
seq
ts
body
```

Every incoming message is checked for:

- A supported protocol version
- Valid frame, JSON, string, and array sizes
- Required fields and correct types
- A session ID matching the current session
- A valid sequence number for the channel
- Duplicate operations where idempotency keys are required
- Nonces, resume keys, and tokens belonging to the current session
- Valid paths, numbers, and timestamps within allowed limits

PeerBay rejects messages from old sessions, reused nonces, invalid sequence numbers, and expired resume keys. Unknown optional fields can be ignored. An unknown required capability disables only the feature that depends on it.

Timestamps are supplementary and never establish trust on their own. Replay protection relies on nonces, session binding, sequence numbers, and token lifetimes.

## Connections and encryption

The control channel is encrypted, and certificates are tied to device identities and fingerprints. If a certificate changes, PeerBay checks it against the stored trust record and requires explicit user approval before continuing.

A session can use separate control, bulk transfer, media, and input channels. A failure in media or file transfer must not disable authentication or policy enforcement on the control channel.

When switching transports, PeerBay uses a `resume_key`. The old channel stays open until the new one is authenticated. If switching fails, the old channel remains available briefly as a fallback. PeerBay avoids executing the same operation twice.

## Privacy

PeerBay sends no external telemetry by default. Diagnostic data stays local unless the user explicitly exports it.

Regular logs never contain:

- Clipboard contents
- SMS or notification contents
- Pairing tokens, private keys, or passwords
- ADB, Shizuku, or root secrets
- File names while privacy mode is active
- Full input payloads
- Private paths or personal information

Clipboard, notifications, files, calls, messages, screen sharing, audio, and input each have their own feature policy. Gaining a higher level of privilege does not automatically enable other features.

Effective access is the intersection of backend capabilities and user and session policies:

```
backend capability
  ∩ user policy
  ∩ session policy
  = effective access
```

## Permissions and privileged access

PeerBay does not represent all permissions with a single `has_access` boolean. Each backend reports its provider, authority, state, limitations, and proof of access.

Supported backends include:

```
standard app
runtime permission
special app access
Accessibility
MediaProjection
Companion Device
USB ADB
Wireless ADB
Shizuku
Sui
root / su
Device Owner
```

Standard app features work without ADB, Shizuku, or root. PeerBay checks for additional privileges only when a feature needs them. Desktop requests cannot silently elevate permissions that require local user action.

Android permission flows work like this:

```
desktop request
  -> phone explains the request locally
  -> user opens the system or provider flow
  -> user confirms locally
  -> phone tests the operation
  -> phone reports available capabilities and limitations
```

### ADB

ADB is a transport or privilege backend, not proof that the entire peer or every feature is trusted.

ADB commands use an allowlist, typed arguments, timeouts, bounded stdout and stderr, child process cancellation, device identity checks, and forward/reverse cleanup when a session ends. Audit events never contain private payloads.

PeerBay never accepts an arbitrary shell string from a peer and executes it directly.

### Shizuku and root

Shizuku is not root. Even when Shizuku runs with root backing through Sui, PeerBay checks authority for each operation. The presence of a Binder service alone does not prove that every capability is available.

Root workers exist only for specific operations, not to run the entire app as root. Root operations use an allowlist, typed arguments, timeouts, expiry, and local policy checks. Root workers stop when their session ends.

### Terminal

Terminal access is separate from normal feature commands.

Feature commands use fixed operation IDs and typed arguments instead of arbitrary shell commands. A terminal session is a separate opt in feature with a warning, policy check, visible peer identity, and cleanup when it ends.

Pairing alone never enables terminal access.

## Threat model

### Threats PeerBay handles

The initial implementation protects against:

- Unapproved devices on the same network
- Fake discovery responses
- Eavesdropping on or tampering with the control channel
- Replay of old tokens or messages
- Certificate changes on trusted peers
- Shared folder escapes through malicious paths or symlinks
- Resource exhaustion caused by oversized payloads or unbounded queues
- Accidental leaks of clipboard contents, notifications, SMS, or file names
- Input state, held keys, or root workers left running after disconnects
- State inconsistencies after helpers or WebViews restart
- Feature operations continuing after permission revocation

### Threats PeerBay cannot fully handle

PeerBay does not claim to protect against:

- Malware running with root or administrator privileges
- A fully compromised operating system
- A malicious PeerBay build installed by the user
- An insecure physical device boot chain
- A trusted peer deliberately abusing its access

These limitations are documented rather than hidden in logs, the UI, or other documentation. PeerBay cannot create a reliable new trust boundary inside an already compromised operating system.

## Safe disconnects

PeerBay stops feature channels and temporary privilege workers when:

- A trust record is removed
- A policy is revoked
- A session times out
- Heartbeats stop
- Protocol validation fails
- The backend requests shutdown
- An Android service stops or a permission is revoked

Input helpers run `release_all` when heartbeats are lost. Disconnects must not leave keys or buttons pressed, or cursor ownership active.

## Implementation checklist

Every feature defines:

1. Its capability ID
2. Its user policy ID
3. Its session policy ID
4. Its message contract
5. Its permission and privilege requirements
6. Its revocation and disconnect behavior
7. Its timeouts and resource limits
8. How it keeps secrets out of logs and view models
9. Its unit, integration, and fault injection tests

Any implementation that breaks these rules requires an update to the threat model and trust boundaries first.
