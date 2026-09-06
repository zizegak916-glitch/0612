# Security policy

## Supported version

Only the latest release line is supported. Please report vulnerabilities privately through GitHub's security advisory interface when available; do not paste subscription URLs, API keys, UUIDs, passwords, or raw provider responses into a public issue.

## Default subscription network boundary

Subscription inspection may:

1. download the user-supplied subscription URL;
2. follow at most four validated redirects;
3. download explicitly referenced proxy-provider documents;
4. resolve node hostnames with the operating system resolver;
5. send only public resolved IP addresses to enabled intelligence providers.

Ordinary subscription inspection must never connect to a node's declared port, perform a proxy-protocol handshake, create a tunnel/VPN, alter routes, or test proxy throughput. Tests enforce that node ports are treated as metadata only.

## Explicit real-test boundary

Android real subscription testing is a separate, opt-in action gated by an impact checkbox and Android's VPN consent UI. It embeds sing-box/libbox, converts selected subscription credentials in memory, rejects node hosts with any private/reserved DNS answer, and establishes a full-device TUN. Core outbound descriptors must pass `VpnService.protect(fd)`; failure aborts instead of risking a routing loop. Other platforms retain the 5.x loopback Mihomo-controller design.

Normal Android completion, error, cancellation and VPN revocation close the command server and TUN descriptor. Browser mode requires one exact node and deliberately holds the VPN until the user presses the notification action. Android permits only one active VPN, and the full-device route can affect every app, so the UI states that effect before requesting consent.

Real-test targets must resolve entirely to public addresses. HTTPS is the default and only option in graphical clients/userscript; the CLI requires a separate flag for public HTTP. Automated probes send no browser cookie, account credential, API key or chat message and cap response bodies. A login redirect is not classified as a geographic block.

## SSRF policy

Public HTTP subscriptions are rejected. Loopback, link-local, private, carrier-grade NAT, multicast, reserved, documentation and otherwise non-global targets are rejected by default. A user may explicitly enable local/private subscription retrieval; mixed public/private DNS answers remain rejected as a rebinding hazard. Redirects are independently revalidated and bodies are capped at 5 MiB.

The opt-in exists for locally hosted subscription managers. It is not applied to node scanning: non-global node addresses are never sent to third-party intelligence services.

## Secrets

No production signing key or API credential belongs in the repository. Android stores saved URLs and API keys with Android Keystore-backed AES-GCM. Desktop/CLI accept optional provider/controller keys from environment variables or explicit secret files; controller secrets are never emitted in reports. iOS saves named subscription URLs only in Keychain when the user requests it and does not persist downloaded subscription bodies or controller secrets. The userscript encrypts saved URLs with a user passphrase and does not save controller secrets.
