# Data sources and freshness

| Source | Fields used | Freshness interpretation |
| --- | --- | --- |
| [ipapi.is](https://ipapi.is/) | Location, ASN, organization; optional security fields | Response time is recorded. Field observation dates are unknown unless the API returns one. |
| [proxycheck.io](https://proxycheck.io/) | Proxy/VPN/type and source-owned risk score | `last_seen` is retained when present. Its risk scale is not averaged with another source. |
| [GeoJS](https://www.geojs.io/) | Backup location, ASN, organization, coordinates/timezone | Response time is recorded; database update time may be unavailable. |
| [RDAP](https://rdap.org/) | Registered range, name, country, type, status and events | Registration/range evidence, not proof of physical device location. |
| [RIPEstat](https://stat.ripe.net/docs/data_api) | BGP visibility, prefix, origin ASN and RPKI validation | Routing observations may change quickly; returned observation timestamps are retained. |
| [Ping0](https://ping0.cc/) | Optional paid IP intelligence | Disabled unless the user supplies `PING0_KEY`; upstream terms and quota apply. |

Current exit checks use several independent echo endpoints and retain disagreements rather than silently choosing one result. Multiple values may be legitimate under IPv4/IPv6 split routing.

AI region policy is a dated local snapshot, not a live contractual promise. The app links to official provider pages and separates static region inference from direct entrance response testing:

- [ChatGPT supported countries](https://help.openai.com/en/articles/7947663-chatgpt-supported-countries)
- [OpenAI API supported countries](https://help.openai.com/en/articles/5347006-openai-api-supported-countries-and-territories)
- [Claude supported countries](https://support.claude.com/en/articles/8461763-where-can-i-access-claude)
- [Gemini web availability](https://support.google.com/gemini/answer/13575153)
- [Gemini mobile availability](https://support.google.com/gemini/answer/14579026)
