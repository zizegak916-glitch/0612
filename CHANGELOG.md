# Changelog

## 5.0.0

- Add single-public-IP detailed investigation with expanded RDAP entities, RIPEstat registration/routing/abuse/visibility, Shodan InternetDB, GreyNoise, PTR and explicit-port TLS certificate capture.
- Add an automatic HTTPS domestic fallback source when global geolocation evidence is insufficient; label it lower-trust and exclude it from high-confidence thresholds.
- Add explicit real subscription testing through an already-running loopback Mihomo/Clash controller and system VPN, including node-name matching, switch confirmation, per-node exit evidence, real AI conversation URLs, custom HTTPS targets and best-effort original-node restoration.
- Add Android foreground-service UI, iOS SwiftUI controls, Windows/Linux desktop tabs, CLI commands and Tampermonkey controls for the new modes.
- Keep ordinary subscription inspection read-only: no node-port connection or protocol handshake. Keep controller secrets, subscription bodies and browser credentials out of reports and storage.

## 4.1.0

- Query independent providers concurrently with per-provider limits, retries, TTL caches and 60-second failure backoff.
- Resolve unique subscription hosts once and download proxy-provider documents concurrently.
- Add majority consensus, explicit field conflicts, source-aware risk-signal states and explainable confidence levels.
- Parallelize current-exit and public AI entrance checks across native clients and the userscript.
- Add force-refresh controls to CLI, desktop, Android and Tampermonkey, plus detailed timing/cache evidence.

## 4.0.0

- Converted the existing project into a multi-platform monorepo.
- Added Windows/Linux desktop UI, terminal CLI, Bash/PowerShell launchers and native iOS SwiftUI app.
- Preserved the Android foreground-service app and upgraded its package version.
- Added operating-system credential storage on desktop and iOS Keychain storage.
- Added CI, multi-platform tagged release builds, security/privacy documentation and executable boundary tests.
- Kept subscription nodes parse/DNS/intelligence-only; no node connection, proxy handshake, VPN or route modification was added.
