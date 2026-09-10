# IPBatchInspector 6.0.0-alpha.2

This release withdraws the failed 6.0.0-alpha.1 VPN experiment and returns the project to a pure-investigation boundary.

## What changed

- Removed Android `VpnService`, embedded sing-box/libbox, native proxy libraries, TUN lifecycle and VPN permissions.
- Removed Mihomo/Clash external-controller code, node switching, custom routed targets and real subscription tests from Python, desktop, iOS and the userscript.
- Subscription investigation now has three explicit classes:
  1. public IP literals directly written in node `server` fields — eligible for IP intelligence;
  2. domain A/AAAA results — DNS infrastructure observations only;
  3. relay, landing, chained or dynamically selected traffic exits — unobservable.
- Removed country allow/deny lists from AI assessment. Hong Kong and every other location receive `not-tested` unless there is a separate current-route HTTP observation; even that observation is not a login or conversation test.
- A web 403 is now `denial-or-challenge-observed`, not an automatic geographic block. API 400/401/403 responses are authentication-frontend observations only.
- Retained and clarified single-public-IP detailed investigation, including RDAP entities, routing/WHOIS/abuse evidence, passive security sources, PTR and explicit-port TLS certificate capture.
- Retained Android notification-visible foreground investigation jobs and user-installed Windows/Linux monitor services, without claiming privileged system-app status.
- Restored the MIT license because the embedded GPL component was removed.

## Installation artifacts

- Android debug APK: installable for device testing, development certificate only.
- Android unsigned APK: audit artifact, not installable until signed.
- Windows installer/portable EXE, Linux DEB/tarball, Python wheel/source distribution, terminal-script bundle and userscript: produced by the release workflow.
- iOS simulator ZIP: not an iPhone IPA; physical-device installation requires the user's Apple signing identity.

Verify release assets with `SHA256SUMS.txt`. Alpha software remains pre-release and must not be described as production- or device-validated until the corresponding test evidence exists.

## Compatibility and migration

- Uninstall or disable 6.0.0-alpha.1 before testing this build. Alpha.2 declares no VPN service and cannot perform node-route tests.
- Saved subscription URLs remain usable. Downloaded subscription bodies and node credentials are not persisted.
- Any monitor configuration using `mode: realtest` now fails validation; change it to `exit`, `ai`, `scan`, `subscription` or `detail`.
- Automation consuming subscription output should use `direct_exposed_public_ips`, `dns_observations` and `unobservable_exit_count`. The compatibility `public_ips` field now contains direct literals only.

## Known limits

- Domain-based subscriptions can legitimately produce zero investigated IPs.
- No subscription node's real egress is observable without connecting through it, and this release deliberately does not connect.
- AI entrance observations are anonymous, current-route and time-scoped. They do not prove logged-in chat, model, account or billing availability.
- Provider data may be incomplete, stale or contradictory. Reports preserve source evidence and failures rather than promising universal truth.
