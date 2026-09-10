# Data sources, freshness and truth boundaries

Last documentation review: 2026-09-09. Links below are primary provider documentation where available. Provider terms, quotas, schemas and coverage can change after this date.

## Standard scan sources

| Source | Fields used | Client cache | Boundary |
| --- | --- | ---: | --- |
| [ipapi.is](https://ipapi.is/developers.html) | Geolocation, ASN, organization; keyed security flags when returned | 6 h | Official docs reviewed 2026-09-09 state 100 anonymous lookups/client IP/UTC day and 1,000/day for a free account. Anonymous minimal responses omit detection flags, so missing flags are unknown. |
| [proxycheck.io](https://proxycheck.io/api/) | Proxy/VPN/type, last-seen and provider-owned risk score | 30 min | Official docs reviewed 2026-09-09 list 100 unregistered and 1,000 registered-free queries/day. Its risk model is not averaged with another vendor. |
| [GeoJS](https://www.geojs.io/) | Backup location, ASN, organization, coordinates and timezone | 24 h | Physical location is an estimate. An upstream dataset timestamp may not be exposed. |
| [RDAP.org](https://about.rdap.org/) | Registered range, handle/name, country, status and events | 7 d | RDAP.org is a bootstrap/redirect service to the responsible registry, not a geolocation database. Its documented public limit is 10 requests per 10 seconds; this client serializes starts. |
| [RIPEstat](https://stat.ripe.net/docs/data-api/ripestat-data-api) | BGP prefix/origin ASN, RPKI and routing observations | 15 min | Routing views depend on collectors and observation time. Client concurrency is capped at eight. |
| Ping0 | Optional provider-specific IP intelligence | 30 min | Disabled unless `PING0_KEY` is supplied. The project does not claim Ping0 affiliation or unrestricted quota. |
| [CIP.cc](https://www.cip.cc/) | Domestic auxiliary location/operator page | 24 h | Used only when fewer than two requested global geolocation sources succeed. It is `fallback-unverified`, not an official mirror and cannot create high confidence. |
| Baidu Intelligent Cloud IP geography endpoint | Android detailed-mode auxiliary text | Not cached | Attempted only after multiple passive-source failures. The response must echo the target IP. It is neither authoritative registry evidence nor a mirror of RDAP/RIPE/Shodan. |

The cache TTL is a local request policy, not a claim about how often a provider rebuilds its database. `--fresh` bypasses this project's cache but cannot force upstream data to be newly measured.

## Detailed investigation sources

| Source | Evidence collected | Important boundary |
| --- | --- | --- |
| RIR RDAP through RDAP.org | Range, current registration name/handle, public entity roles/contact fields, status and events | The registrant or allocation holder is not necessarily the current server operator, customer or physical owner. Country is administrative. |
| RIPEstat Network Info / WHOIS / Abuse / Visibility | Covering prefix, origin ASN, registry/IRR records, published abuse contacts and RIS visibility | Records can disagree or be incomplete. Visibility is not uptime. |
| [Shodan InternetDB](https://internetdb.shodan.io/) | Passive hostnames, ports, CPEs, CVEs and tags | No active port scan occurs. Old associations and version ambiguity can make CVE matches stale or inapplicable. |
| [GreyNoise Community](https://docs.greynoise.io/docs/using-the-greynoise-community-api) | Noise/scanner/RIOT classification and last-seen fields | No record is not proof of safety. Community results are coverage-limited. |
| PTR/rDNS | Current resolver answer | The reverse name is controlled by an address holder and does not prove service ownership. |
| Active TLS observation | Leaf certificate, SHA fingerprints, subject, issuer, SAN, validity, negotiated protocol/cipher | Only explicit ports are contacted. Default is 443. Unknown SNI/shared hosting may return a default certificate. |
| Optional Shodan/GreyNoise/VirusTotal keyed APIs | Additional account-authorized passive observations | Vendor account, plan, quota and terms apply. Keys are not serialized into reports. |

## Current exit

Exit detection queries independent echo endpoints over the process's current default route. If endpoints report different addresses, the report retains all values. Differences can be legitimate with IPv4/IPv6 split routing, DNS policy, per-app VPN rules or transparent proxies. The observation describes this process, not necessarily every app on the device.

## AI endpoints and policy references

The current-route AI check sends anonymous requests without cookies, credentials, API keys, prompts or chat messages. Redirects are not automatically followed. Results are time-stamped HTTP/transport observations.

The dated OpenAI reference is [OpenAI API supported countries and territories](https://developers.openai.com/api/docs/supported-countries), reviewed 2026-09-09. Its own heading and text identify API services as the scope. The application must not reinterpret it as a ChatGPT web allowlist. In particular, absence or presence of a country on this API page does not override direct user evidence about ChatGPT web access.

The project contains no country allowlist/denylist for AI availability. It does not query subscription nodes through a proxy and cannot test their AI access.

## What “truthful” means here

The software can make reproducible claims about:

- the exact target requested;
- the source endpoint attempted;
- the UTC query time, duration, cache state and error;
- fields actually returned and conflicts among sources;
- whether a TLS handshake to an explicit IP/port succeeded at that moment.

It cannot guarantee:

- that a third-party record is correct, complete or current;
- that an IP's registrant, routing origin, hosting customer and physical operator are the same entity;
- that passive ports/CVEs remain present;
- that an account, website, model or subscription will accept the IP;
- that all public Internet information has been found.

Reports preserve these limits instead of replacing unknowns with confident labels.
