# Data sources and freshness

| Source | Fields used | Default cache | Freshness / quota interpretation |
| --- | --- | ---: | --- |
| [ipapi.is](https://ipapi.is/developers.html) | Location, ASN, organization; optional security fields | 6 h | Official docs currently list anonymous use as 100 requests/day with a minimal response and a free account as 1,000/day. Missing keyed-only fields are **unknown**, not false. The provider says its underlying data is updated at least weekly. |
| [proxycheck.io](https://proxycheck.io/api/) | Proxy/VPN/type, `last_seen` and source-owned risk score | 30 min | `risk=1`, `vpn=1`, `asn=1`, `seen=1` are requested. Official docs currently list 100/day unregistered and 1,000/day for a registered free key; its risk scale is not averaged with another source. |
| [GeoJS](https://www.geojs.io/) | Backup location, ASN, organization, coordinates/timezone | 24 h | Response time is recorded; database update time may be unavailable. |
| [RDAP.org](https://about.rdap.org/) | Registered range, name, country, type, status and events | 7 d | Registration/range evidence, not physical geolocation. Public redirect service documents a maximum of 10 requests per 10 seconds; the clients throttle this path. |
| [RIPEstat](https://stat.ripe.net/docs/data-api/ripestat-data-api) | BGP visibility, prefix, origin ASN and RPKI validation | 15 min | Routing observations may change quickly. Returned observation timestamps are retained and client concurrency is capped at 8. |
| [Ping0](https://ping0.cc/) | Optional paid IP intelligence | 30 min | Disabled unless the user supplies `PING0_KEY`; upstream terms and quota apply. |

`--fresh` bypasses cache reads and refreshes successful entries. A fresh HTTP response does not mean every upstream field was freshly measured at request time.

Current exit checks use several independent echo endpoints and retain disagreements rather than silently choosing one result. Multiple values may be legitimate under IPv4/IPv6 split routing.

AI region policy is a dated local snapshot, not a live contractual promise. The app links to official provider pages and separates static region inference from direct entrance response testing:

- [ChatGPT supported countries](https://help.openai.com/en/articles/7947663-chatgpt-supported-countries)
- [OpenAI API supported countries](https://help.openai.com/en/articles/5347006-openai-api-supported-countries-and-territories)
- [Claude supported countries](https://support.claude.com/en/articles/8461763-where-can-i-access-claude)
- [Gemini web availability](https://support.google.com/gemini/answer/13575153)
- [Gemini mobile availability](https://support.google.com/gemini/answer/14579026)
