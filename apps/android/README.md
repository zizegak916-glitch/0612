# Android client

Native Java client for Android 6.0/API 23 and later, targeting API 35. It uses foreground services for user-started scans, encrypted local storage for saved subscription URLs/keys, and the Android system default route.

Build with `./build.sh`. The script downloads toolchain files into `.toolchain/`, runs parser/downloader smoke tests and creates `build/IPBatchInspector-v5.0.0-android-debug.apk` with a local debug signature. Do not publish that debug key or represent this artifact as a store-signed release.

The Android implementation is intentionally independent of the Python package so it can use Android Keystore, foreground-service and notification APIs without embedding a Python runtime.
