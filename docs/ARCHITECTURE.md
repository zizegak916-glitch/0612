# Architecture and trust model

## Components

```mermaid
flowchart TD
  U[User input] --> P[Subscription/IP parser]
  P --> R[OS DNS resolution]
  R --> G{Public IP?}
  G -- no --> L[Local-only finding]
  G -- yes --> I[IP intelligence sources]
  I --> E[Evidence-normalized result]
  C[Current system route] --> X[Exit and AI entrance checks]
  X --> E
  D["Detailed mode: one public IP"] --> I
  D --> T["Explicit TLS port"]
  S["Android real-test opt-in"] --> M["Embedded libbox"]
  M --> V["Android VpnService TUN"]
  V --> A["Conversation/custom URLs"]
```

The Python package is the reference implementation for Windows, Linux, terminal and scripts. Android and iOS are native clients because background execution, secure storage and network-policy APIs differ significantly by operating system.

## Evidence model

Normalized display fields never erase source evidence. Each source has its own status, timestamp, elapsed time, payload-derived fields and sanitized error. A merged country/ASN is a convenience view; conflicting source values remain visible in `evidence`.

Risk is not averaged. `risk_scores` maps every score to its originating provider. Boolean proxy/VPN/Tor/datacenter flags are cumulative signals, not proof of wrongdoing.

## Subscription flow

The downloader validates scheme, userinfo, host, resolved address class, redirect count and body size. Parsing accepts URI lists, nested Base64 and Clash/Mihomo YAML. Provider documents pass through the same downloader. The resolver reads only node server names and runs DNS; node port values never enter a connection API.

## Detailed investigation flow

Detailed mode accepts exactly one public address. Passive registration, routing, security and rDNS lookups execute independently and retain their own timing/error records. Active target traffic is a TLS handshake only on the requested port list, defaulting to 443; there is no range scan. Hostnames discovered through passive/PTR evidence are used as SNI candidates only when current DNS resolves them back to the target IP. A domestic mirror is requested only after insufficient global geolocation results and is excluded from the high-confidence count.

## Real subscription test flow

On Android, the real-test branch is reachable only after a separate impact checkbox and OS VPN consent. It downloads the subscription before TUN creation, converts one node at a time to an isolated sing-box configuration, rejects private/reserved node resolutions, establishes the TUN through `VpnService.Builder`, and passes outbound socket descriptors through `protect(fd)`. Capped anonymous requests then reach validated public conversation/custom URLs. Normal completion, error, cancellation and VPN revocation close the core and descriptor. Other platforms retain the 5.x loopback Mihomo-controller implementation.

## AI conclusions

Direct entrance checks, node-IP inference and explicit system-VPN real tests are deliberately separate. Direct tests show only the response class seen over the current device route. Region-policy inference is versioned static evidence plus IP metadata. Real tests switch a user-owned companion VPN and access the actual conversation URL, but anonymous automated probes still do not authenticate, submit a prompt, test paid models or guarantee future availability.
