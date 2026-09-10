# Security policy

## Supported version

Only the latest release line is supported. Report vulnerabilities privately through GitHub's security advisory interface when available. Never paste subscription URLs, API keys, UUIDs, passwords or raw provider responses into a public issue.

Version 6.0.0-alpha.1 is withdrawn. The current code must not contain its VPN/libbox or external-controller execution paths.

## Subscription network boundary

Subscription inspection may:

1. download a user-supplied subscription URL;
2. follow at most four independently validated redirects;
3. download explicitly referenced provider documents;
4. parse supported metadata and redact secrets;
5. resolve node domains using the operating-system resolver;
6. send only public IP literals directly written in node `server` fields to selected intelligence sources.

Subscription inspection must never connect to a declared node port, perform a proxy handshake, create a tunnel/VPN, change routes, select an external controller node, test throughput or claim a real exit. Domain DNS answers are output under `dns_observations` only. CI and unit tests enforce this separation and reject reintroduction of known VPN/controller paths.

## SSRF policy

Public HTTP subscriptions are rejected. HTTPS is required unless a user explicitly opts into retrieving a local/private subscription manager. Every redirect is revalidated, response bodies are capped at 5 MiB and mixed public/private DNS answers are rejected as a rebinding hazard.

The private-subscription opt-in affects only document retrieval. It never permits non-global node addresses to be sent to public intelligence providers.

Custom AI targets and subscription-node targets do not exist in the pure-investigation build.

## Active connections

Normal batch IP intelligence contacts only selected public provider endpoints. Detailed mode additionally opens TLS connections only to the single user-supplied public IP and explicit ports, defaulting to 443. It is not a port scanner. AI entrance observation contacts a fixed list of public provider frontends over the device's existing default route.

Android foreground services are `dataSync` services. The manifest contains no `VpnService`, VPN foreground-service type or network-extension privilege.

## Secrets

No production signing key or API credential belongs in the repository. Provider keys come from environment variables or platform secure storage and must never be serialized into reports. Android stores saved URLs/API keys using Android Keystore-backed AES-GCM. iOS saves requested subscription URLs in Keychain. Desktop/CLI use the operating-system credential store when the optional dependency is installed. The userscript encrypts saved URLs using a user passphrase.

## Reporting a vulnerability

Include the affected version, platform, exact input class, expected boundary and observed behavior. Redact all live credentials and replace real subscription hosts with reproducible test fixtures.
