# Security policy

## Supported version

Only the latest release line is supported. Please report vulnerabilities privately through GitHub's security advisory interface when available; do not paste subscription URLs, API keys, UUIDs, passwords, or raw provider responses into a public issue.

## Non-negotiable network boundary

Subscription inspection may:

1. download the user-supplied subscription URL;
2. follow at most four validated redirects;
3. download explicitly referenced proxy-provider documents;
4. resolve node hostnames with the operating system resolver;
5. send only public resolved IP addresses to enabled intelligence providers.

Subscription inspection must never connect to a node's declared port, perform a proxy-protocol handshake, create a tunnel/VPN, alter routes, or test proxy throughput. Tests enforce that node ports are treated as metadata only.

## SSRF policy

Public HTTP subscriptions are rejected. Loopback, link-local, private, carrier-grade NAT, multicast, reserved, documentation and otherwise non-global targets are rejected by default. A user may explicitly enable local/private subscription retrieval; mixed public/private DNS answers remain rejected as a rebinding hazard. Redirects are independently revalidated and bodies are capped at 5 MiB.

The opt-in exists for locally hosted subscription managers. It is not applied to node scanning: non-global node addresses are never sent to third-party intelligence services.

## Secrets

No production signing key or API credential belongs in the repository. Android stores saved URLs and API keys with Android Keystore-backed AES-GCM. Desktop/CLI accept optional keys from environment variables and do not implement a credential vault. iOS stores saved values in app-local preferences only when the UI explicitly offers that feature; the current iOS client does not persist raw subscriptions.
