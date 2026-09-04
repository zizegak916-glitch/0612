# Data sources and freshness

| Source | Fields used | Default cache | Freshness / quota interpretation |
| --- | --- | ---: | --- |
| [ipapi.is](https://ipapi.is/developers.html) | Location, ASN, organization; optional security fields | 6 h | Official docs currently list anonymous use as 100 requests/day with a minimal response and a free account as 1,000/day. Missing keyed-only fields are **unknown**, not false. The provider says its underlying data is updated at least weekly. |
| [proxycheck.io](https://proxycheck.io/api/) | Proxy/VPN/type, `last_seen` and source-owned risk score | 30 min | `risk=1`, `vpn=1`, `asn=1`, `seen=1` are requested. Official docs currently list 100/day unregistered and 1,000/day for a registered free key; its risk scale is not averaged with another source. |
| [GeoJS](https://www.geojs.io/) | Backup location, ASN, organization, coordinates/timezone | 24 h | Response time is recorded; database update time may be unavailable. |
| [RDAP.org](https://about.rdap.org/) | Registered range, name, country, type, status and events | 7 d | Registration/range evidence, not physical geolocation. Public redirect service documents a maximum of 10 requests per 10 seconds; the clients throttle this path. |
| [RIPEstat](https://stat.ripe.net/docs/data-api/ripestat-data-api) | BGP visibility, prefix, origin ASN and RPKI validation | 15 min | Routing observations may change quickly. Returned observation timestamps are retained and client concurrency is capped at 8. |
| [Ping0](https://ping0.cc/) | Optional paid IP intelligence | 30 min | Disabled unless the user supplies `PING0_KEY`; upstream terms and quota apply. |
| [CIP.cc](https://www.cip.cc/) | Domestic alternative location/operator text | 24 h | HTTPS fallback only when fewer than two requested global geolocation sources succeed. It is marked `fallback-unverified`, is not an authoritative registry and cannot raise confidence to high. |

Detailed mode additionally queries the following, without treating availability as truth:

| Detailed source | Evidence | Important boundary |
| --- | --- | --- |
| [IANA/RIR RDAP](https://www.iana.org/assignments/rdap-ipv4/) via `rdap.org` | Current registered range, handle, entity roles/public vCard fields, status and events | Registration holder and country are administrative data, not guaranteed physical location. |
| [RIPEstat Network Info](https://stat.ripe.net/docs/data-api/api-endpoints/network-info) | Covering prefix and origin ASN | Routing state can change. |
| [RIPEstat WHOIS](https://stat.ripe.net/docs/data-api/api-endpoints/whois) | Registry and IRR records | Records can conflict across authorities. |
| [RIPEstat Abuse Contact Finder](https://stat.ripe.net/docs/data-api/api-endpoints/abuse-contact-finder) | Published abuse contacts | RIPE explicitly warns contacts can be missing or incorrect. |
| [RIPEstat Visibility](https://stat.ripe.net/docs/data-api/api-endpoints/visibility) | RIS peer visibility | Visibility is an observation, not uptime. |
| [Shodan InternetDB](https://internetdb.shodan.io/) | Passive hostnames, ports, CPEs, CVEs and tags | No active port scan is performed; observations can be old and a CVE association is not proof of current exploitability. |
| [GreyNoise Community](https://docs.greynoise.io/docs/using-the-greynoise-community-api) | Scanner/noise/RIOT classification and last seen where available | Anonymous community lookup is limited; HTTP 404 means no community record, not a network failure. |
| Active TLS observation | Leaf certificate, fingerprints, names, validity, negotiated TLS/cipher on explicit ports | Captured without using the certificate as a trust decision; unknown SNI can produce a different shared-hosting certificate. |
| Optional Shodan/GreyNoise/VirusTotal keyed APIs | Extra passive observations when the corresponding environment key is configured | Vendor account, plan, quota and terms apply; keys are never serialized into reports. |

The project does not claim that this list is “all information on the Internet.” Search indexes, private feeds and historical datasets have different coverage and update times. The durable guarantee is narrower: every attempted source, timestamp, latency, response status/fields and failure is represented in the report.

`--fresh` bypasses cache reads and refreshes successful entries. A fresh HTTP response does not mean every upstream field was freshly measured at request time.

Current exit checks use several independent echo endpoints and retain disagreements rather than silently choosing one result. Multiple values may be legitimate under IPv4/IPv6 split routing.

AI region policy is a dated local snapshot, not a live contractual promise. The app links to official provider pages and separates static region inference from direct entrance response testing:

- [ChatGPT supported countries](https://help.openai.com/en/articles/7947663-chatgpt-supported-countries)
- [OpenAI API supported countries](https://help.openai.com/en/articles/5347006-openai-api-supported-countries-and-territories)
- [Claude supported countries](https://support.claude.com/en/articles/8461763-where-can-i-access-claude)
- [Gemini web availability](https://support.google.com/gemini/answer/13575153)
- [Gemini mobile availability](https://support.google.com/gemini/answer/14579026)

Real subscription tests use the local [Mihomo external controller API](https://wiki.metacubex.one/en/api/) to verify TUN configuration, enumerate/select a policy-group node and restore the prior selection. The subscription itself is still parsed without a node connection. The HTTP probes target conversation URLs, do not follow redirects automatically, cap response bodies and never attach user cookies or credentials. A target result is a time-stamped network observation, not a promise that a logged-in account or model will remain usable.
