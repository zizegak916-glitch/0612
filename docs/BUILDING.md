# Building and packaging

## Python, CLI, Windows and Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip build pyinstaller
python -m build
python -m PyInstaller --clean --paths src --onefile --name ipbatch-cli scripts/ip_inspector.py
python -m PyInstaller --clean --paths src --onefile --windowed --name IPBatchInspector apps/desktop/launcher.py
```

On Windows use `py` instead of `python3`. Tk must be present in the Python distribution. CI builds on native Windows and Ubuntu runners because executables are platform-specific.

Windows Inno Setup 6:

```powershell
& "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe" /DMyAppVersion=6.0.0-alpha.2 packaging\windows\IPBatchInspector.iss
```

Linux, after PyInstaller creates `dist/IPBatchInspector` and `dist/ipbatch-cli`:

```bash
./packaging/linux/build_packages.sh 6.0.0~alpha.2
```

The DEB installs a systemd user-service template but does not silently enable it. Windows service setup likewise requires the user to run `scripts/install_service_windows.ps1`.

## Android

`apps/android/build.sh` downloads checksum-pinned Android 35 platform/build-tools, Eclipse ECJ 3.37.0 and org.json 20240303. It does not download an NDK, Go, sing-box or libbox. It compiles Java, runs parser/downloader smoke tests, builds DEX, packages resources and verifies the generated signature.

```bash
cd apps/android
chmod +x build.sh
./build.sh
```

Without signing variables the script creates an installable development-signed APK and an unsigned audit APK. A public release uses a separately protected key:

```bash
IPBATCH_KEYSTORE=/secure/release.jks \
IPBATCH_KEY_ALIAS=release \
IPBATCH_KEYSTORE_PASSWORD='...' \
IPBATCH_KEY_PASSWORD='...' \
./build.sh
```

GitHub Actions secret names are `ANDROID_KEYSTORE_BASE64`, `ANDROID_KEY_ALIAS`, `ANDROID_KEYSTORE_PASSWORD` and `ANDROID_KEY_PASSWORD`. When these are absent, artifacts are explicitly named debug/unsigned and must not be represented as production-signed.

## iOS

Open `apps/ios/IPBatchInspector.xcodeproj` in Xcode 16 or newer. The target is iOS 16+. A simulator build needs no signing. A physical iPhone build requires the user's Apple development team and provisioning profile. CI's simulator ZIP is not an IPA.

## Tampermonkey

`userscript/IPBatchInspector.user.js` is the installable script. Validate syntax with:

```bash
node --check userscript/IPBatchInspector.user.js
```

It declares `@connect *` because a subscription host is user-supplied and cannot be enumerated in advance. URL saving uses PBKDF2-SHA256 (210,000 iterations) and AES-256-GCM with a user passphrase. The userscript cannot become an operating-system background service or directly inspect arbitrary TLS handshakes.

## Test commands

```bash
python -m unittest discover -s tests -v
node --check userscript/IPBatchInspector.user.js
cd apps/android && ./build.sh
```

On macOS with Xcode, also run the simulator `xcodebuild` command from `.github/workflows/ci.yml`.

## Release workflow

A version manifest in `.github/releases/vX.Y.Z.json`, after review and merge to `main`, drives native-runner builds, SHA-256 generation and GitHub Release publication. Workflow artifacts, debug Android signatures, unsigned iOS simulator apps, unsigned Windows binaries and unsigned Linux packages are not equivalent to store/distribution signatures.

Version 6.0.0-alpha.1 is withdrawn. Do not reuse its release title, artifacts or VPN capability claims for alpha.2.
