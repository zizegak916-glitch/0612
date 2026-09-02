# Contributing

Run `make test lint` before submitting changes. Android changes must also pass `cd apps/android && ./build.sh`; iOS changes must build with the repository Xcode scheme on a macOS runner.

Changes to subscription handling must preserve the non-connection invariant. A node's `port` may be parsed, displayed and exported but must never be passed to a socket, URLSession, proxy, VPN or tunnel API. New download redirects/providers must pass through the same scheme, SSRF, redirect and size policy.

Provider normalization should retain original source evidence, timestamp and errors. Do not label a missing risk flag as “safe”, average unrelated risk scores, or label an HTTP 403 as a proven geographic block without explicit response evidence.
