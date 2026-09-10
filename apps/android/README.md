# Android client · 6.0.0-alpha.2

Native Java client for Android 7/API 24 and later, targeting API 35. It is an investigation-only application: there is no `VpnService`, TUN engine, proxy protocol implementation, node connection or route change.

User-started batch scans, current-route AI entrance observations and single-IP detailed investigations run in notification-visible `dataSync` foreground services. This lets work continue while the activity is not visible, subject to Android process, battery and network policies. It does not make the app root, a system UID application or a privileged `/system/priv-app`.

Subscription inspection downloads and parses text only. A public IP literal directly present in a node `server` field may be sent to enabled IP-intelligence sources. Domain A/AAAA answers are displayed separately as DNS infrastructure observations and are never treated as node or exit IPs. Hidden relay, landing and chain exits are unobservable because the app never connects to a node.

`./build.sh` downloads checksum-pinned Android 35 platform/build-tools, ECJ and org.json, compiles Java, runs parser/downloader smoke tests, and creates:

- `build/IPBatchInspector-v6.0.0-alpha.2-android-debug.apk`: installable, development-signed.
- `build/IPBatchInspector-v6.0.0-alpha.2-android-unsigned.apk`: audit artifact, not installable without signing.
- A `-release.apk` only when the caller supplies the four protected signing variables documented in `docs/BUILDING.md`.

The manifest requests INTERNET, network-state, foreground data-sync, notification and wake-lock permissions. It declares no VPN service or VPN-related foreground-service type. A physical-device test is still required before describing a build as device-validated.
