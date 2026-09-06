# Android client · 6.0.0-alpha.1

Native Java client for Android 7/API 24 and later, targeting API 35. Ordinary scans use foreground services and never connect to subscription node ports. Explicit real mode is a separate, user-confirmed `android.net.VpnService` backed by sing-box/libbox 1.14.0.

`./build.sh` produces an installable debug APK and an unsigned audit APK. On its first clean run it downloads fixed toolchains, checks out sing-box commit `0b8995879f29a9b98ee027bc17b75e101445b238`, builds libbox for arm64-v8a, armeabi-v7a, x86_64 and x86, compiles Java, runs parser/config/downloader smoke tests, packages native libraries and verifies the APK signature. Cached inputs live in ignored `.native/` and `.toolchain/` directories.

The debug certificate is for local installation only. A public release must provide the four signing variables documented in `docs/BUILDING.md`. This alpha has compile/package verification but is not declared device-validated until a physical Android device completes VPN consent, at least one real node test, cancellation and process-restart testing.
