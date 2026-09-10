# IPBatchInspector 6.0.0-alpha.1 — Embedded Android system VPN

This alpha replaces Android's external-controller real test with an in-app,
user-consented `android.net.VpnService` powered by a pinned sing-box/libbox
1.14.0 build.

## What is real in this build

- Android displays the operating system VPN consent screen and establishes a
  full-device IPv4/IPv6 TUN only from the separately confirmed real-test path.
- Common VLESS, VMess, Shadowsocks, Trojan, Hysteria/Hysteria2, TUIC, SOCKS,
  HTTP, Clash `dialer-proxy`, and sing-box `detour` nodes are converted into
  isolated temporary configurations. Unsupported records are reported rather
  than silently treated as successful.
- Every node server is resolved before the TUN is opened. Literal or resolved
  private, reserved, documentation, loopback, link-local, and CGNAT addresses
  are rejected. The core's outbound sockets must pass `VpnService.protect(fd)`.
- The app re-detects its public exit and requests the real conversation URLs
  for ChatGPT, Claude, Gemini, AI Studio, Grok, Perplexity, and Copilot, plus
  user-supplied public HTTPS targets. It does not send cookies, credentials,
  prompts, or chat messages.
- Ordinary subscription inspection remains parse-and-resolve only and has no
  reference to the VPN service or libbox command server.

## Investigation and evidence changes

- Single-IP investigation now queries labelled RDAP, direct RIR fallback,
  RIPEstat registration/routing/abuse/visibility, Shodan InternetDB,
  GreyNoise Community, PTR, and a bounded 443/TLS certificate observation.
- RDAP bootstrap timeouts, rate limits, server errors, and 404 responses fall
  through to the five direct RIR endpoints.
- Domestic auxiliary pages run only after multiple core-source failures and
  remain visibly labelled as non-authoritative; they cannot overwrite RIR or
  BGP evidence.

## Build and validation status

- Pinned source: sing-box commit
  `0b8995879f29a9b98ee027bc17b75e101445b238`.
- Embedded AAR SHA-256:
  `bb7e98ea2f68507d0998cd61d60cba7fc45d98cb93b6d77f626846b4c54d30dc`.
- Builds arm64-v8a, armeabi-v7a, x86_64, and x86 native libraries. Toolchain,
  dependency JAR, and cached AAR hashes are enforced before compilation.
- Java compilation, parser/config/downloader smoke tests, official sing-box
  schema checks, APK structure inspection, and APK v2/v3 signature validation
  have passed in the development environment.

This is deliberately labelled alpha because no physical Android-device VPN
session was available during this build. A downloadable debug APK is
installable but uses a development certificate. A stable release requires a
retained private release key plus physical-device tests covering consent,
real-node routing, cancellation, revocation, backgrounding, and process death.

## Platform boundary

Windows, Linux, terminal, iOS, and Tampermonkey packages remain the 5.x
external-Mihomo-controller implementation in this milestone. The iOS simulator
archive is not an iPhone IPA, and the userscript is not a system VPN or
background service.
