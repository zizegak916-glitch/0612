# IPBatchInspector 5.0.0 — Detailed evidence and real system-VPN tests

This major release adds two opt-in modes while retaining the read-only default subscription boundary.

## Single-IP detailed investigation

- Exactly one public IPv4/IPv6 target; local, reserved, CGNAT and documentation ranges are rejected before any provider request.
- Expanded public evidence from standard sources, RDAP entities, RIPEstat network/WHOIS/abuse/visibility, Shodan InternetDB, GreyNoise and reverse DNS.
- Active TLS observation only on explicitly requested ports (443 by default), including leaf certificate metadata/fingerprints and negotiated TLS details. This is not a port scan.
- Optional keyed Shodan, GreyNoise and VirusTotal evidence when users supply their own environment keys.
- CIP.cc HTTPS domestic fallback when fewer than two global geolocation sources succeed. It is visibly lower-trust and cannot create a high-confidence conclusion.

## Real subscription route testing

- Requires an already-running, user-authorized Mihomo/Clash-compatible system VPN and loopback External Controller.
- Downloads the subscription only for safe parsing and node-name matching. It never connects to node ports or implements proxy protocols.
- Switches a controller policy group, verifies the actual node, records the route exit, and probes real ChatGPT, Claude, Gemini, AI Studio, Grok, Perplexity, Copilot, DeepSeek and Qwen conversation URLs plus custom public HTTPS targets.
- Does not send browser cookies, account credentials, API keys, prompts or chat messages. Login redirects count as reachability, not geo-blocking; only explicit region text is classified as a region block.
- Restores the original node after ordinary tests. Browser mode requires one exact node and intentionally leaves it selected so the user's authenticated browser can test the actual page.

## Platform notes

- Android advanced tasks run as notification-visible foreground services and can continue with the UI backgrounded.
- iOS requests the limited background execution time allowed to ordinary apps; iOS can still suspend long jobs.
- Windows/Linux expose both modes in the desktop application and CLI. Linux systemd and Windows scheduled-task monitoring remain user-installed and opt-in.
- Tampermonkey supports passive detailed investigation and loopback controller tests, but cannot read the live TLS certificate exposed to the browser and cannot become a system background service.

## Truth and safety

No client can guarantee every public record or permanent AI availability. Reports enumerate actual sources, query times, latencies, failures, conflicts and limitations. Passive port/CVE/risk data may be stale. Registration country is not physical location. Real-test results can differ from a browser when split-tunnel or per-application routing rules apply.
