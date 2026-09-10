# Privacy

IPBatchInspector has no project-operated analytics, telemetry or backend.

When the user starts a check, the device contacts selected third-party intelligence services. Those services can observe the queried IP, the caller's current exit IP, request metadata and time. Exit detection necessarily contacts external echo services. AI entrance observation contacts the named AI services anonymously. Detailed investigation additionally performs TLS handshakes to the exact target IP and explicitly selected ports, so the target network can observe those connections.

Subscription text can contain credentials. Downloaded text is kept in process memory only as long as needed for parsing. Reports contain redacted node metadata and do not include passwords, UUIDs, userinfo, subscription tokens or raw subscription bodies.

Saved subscription URLs use Android Keystore-backed encryption, iOS Keychain, an operating-system credential store on desktop/CLI, or passphrase-derived AES-GCM in the userscript. CLI shell history is outside the application's control; on shared systems prefer `--url-file` or a saved name instead of placing a sensitive URL directly on the command line.

Subscription inspection does not connect to a node. Public IP literals written directly in node `server` fields may be sent to enabled intelligence providers. Domain A/AAAA answers are retained only as DNS observations and are not sent through the node-IP investigation pipeline. Private, reserved, loopback, link-local, multicast, CGNAT and documentation addresses are blocked from public intelligence queries.

AI probes use fresh anonymous HTTP requests without browser cookies, account credentials, API keys, prompts or messages. The application does not open logged-in conversation sessions.

CSV/JSON exports may contain IP addresses, ASN, organization, approximate location, node display names, DNS observations and provider evidence. Review exports before sharing.
