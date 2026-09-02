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

On Windows use `py` instead of `python3`; omit `--windowed` when diagnostic console output is desired. Tk must be included in the Python distribution. CI builds on native Windows and Ubuntu runners so produced executables are platform-specific.

Windows 安装向导使用 Inno Setup 6：

```powershell
& "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe" /DMyAppVersion=4.0.0 packaging\windows\IPBatchInspector.iss
```

Linux 在生成 `dist/IPBatchInspector` 与 `dist/ipbatch-cli` 后可打 DEB 和便携包：

```bash
./packaging/linux/build_packages.sh 4.0.0
```

## Android

`apps/android/build.sh` downloads the official Android 35 platform/build tools and Eclipse compiler into an ignored local toolchain directory and runs parser/downloader tests. Without signing variables it creates an installable debug APK and an unsigned audit APK. A public release must use a separately protected signing key; the repository never contains one.

```bash
cd apps/android
chmod +x build.sh
./build.sh
```

正式签名入口：

```bash
IPBATCH_KEYSTORE=/secure/release.jks \
IPBATCH_KEY_ALIAS=release \
IPBATCH_KEYSTORE_PASSWORD='...' \
IPBATCH_KEY_PASSWORD='...' \
./build.sh
```

GitHub Actions 对应 Secrets 为 `ANDROID_KEYSTORE_BASE64`、`ANDROID_KEY_ALIAS`、`ANDROID_KEYSTORE_PASSWORD` 和 `ANDROID_KEY_PASSWORD`。没有这四项时发布页只会出现名称明确的 debug/unsigned APK，绝不把开发签名冒充正式签名。

## iOS

Open `apps/ios/IPBatchInspector.xcodeproj` in Xcode 16 or newer. The project builds for iOS 16+. Select a simulator for an unsigned build. Running on a physical device requires the user's own Apple development team and provisioning profile.

## Tampermonkey

`userscript/IPBatchInspector.user.js` 是完整可安装脚本。修改后至少执行：

```bash
node --check userscript/IPBatchInspector.user.js
```

它用 GM 跨域请求访问用户输入的订阅域名，因此元数据必须声明 `@connect *`。保存 URL 时使用 PBKDF2-SHA256（210,000 次）派生 AES-256-GCM 密钥，用户口令不保存。

## Release workflow

新增 `.github/releases/vX.Y.Z.json` 并推送到 `main`。Release 工作流会读取清单、在原生 runner 编译安装包、生成 `SHA256SUMS.txt`，最后由 GitHub token 创建标签和 Release。重复运行会覆盖同一标签的构建资产，不会创建假版本。

A workflow artifact, debug-signed Android APK or unsigned iOS simulator build is not the same as a store-signed release. Windows Authenticode、Android 稳定发布证书、Apple 真机签名和 Linux 发行仓库签名都必须由各自私钥持有人完成。
