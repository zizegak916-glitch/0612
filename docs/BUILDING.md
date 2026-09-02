# Building and packaging

## Python, CLI, Windows and Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip build pyinstaller
python -m build
pyinstaller --clean --paths src --onefile --name ipbatch-cli scripts/ip_inspector.py
pyinstaller --clean --paths src --onefile --windowed --name IPBatchInspector apps/desktop/launcher.py
```

On Windows use `py` instead of `python3`; omit `--windowed` when diagnostic console output is desired. Tk must be included in the Python distribution. CI builds on native Windows and Ubuntu runners so produced executables are platform-specific.

## Android

`apps/android/build.sh` downloads the official Android 35 platform/build tools and Eclipse compiler into an ignored local toolchain directory, runs parser/downloader tests, then creates a debug-signed APK. A public release must use a separately protected signing key; the repository never contains one.

```bash
cd apps/android
chmod +x build.sh
./build.sh
```

## iOS

Open `apps/ios/IPBatchInspector.xcodeproj` in Xcode 16 or newer. The project builds for iOS 16+. Select a simulator for an unsigned build. Running on a physical device requires the user's own Apple development team and provisioning profile.

## Release workflow

Push a semantic tag such as `v4.0.0`. The release workflow compiles and tests on native runners and uploads artifacts. A workflow artifact or unsigned iOS simulator build is not the same as an App Store/TestFlight release.
