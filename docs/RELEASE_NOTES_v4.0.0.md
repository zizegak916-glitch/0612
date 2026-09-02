# IPBatchInspector 4.0.0

首个多平台正式发布流水线版本，包含 Android、iOS 验证包、Windows、Linux、终端和油猴脚本。

## 直接安装

- **Windows 10/11 x64**：下载 `Windows-x64-Setup.exe`。当前项目没有 Authenticode 证书，Windows 可能显示 SmartScreen 提示；请先核对 `SHA256SUMS.txt`。
- **Linux x86_64（Debian/Ubuntu）**：下载 `.deb` 后运行 `sudo apt install ./文件名.deb`；也提供免安装 `.tar.gz`。
- **Android 6+**：有 `android-release.apk` 时表示仓库管理员已配置受保护的发布密钥；否则 `android-debug.apk` 可侧载验证，但它是开发证书，不能与未来正式签名版本原位升级。`android-unsigned.apk` 仅供审计/重签，不能直接安装。
- **终端**：下载 Python wheel 后运行 `python -m pip install ./ipbatch_inspector-4.0.0-py3-none-any.whl`，或使用 terminal scripts 压缩包。
- **油猴/Tampermonkey**：下载或直接打开 `IPBatchInspector-4.0.0.user.js`，确认权限后安装。

## iOS 的真实边界

`iOS-Simulator.zip` 是 CI 编译通过的模拟器应用，不是可安装到 iPhone 的 IPA。真机 IPA、TestFlight 或 App Store 包必须由持有 Apple 开发者证书与描述文件的人签名，仓库不会伪造或公开私钥。

## 网络和隐私边界

- 订阅只下载、解析、系统 DNS/DoH 解析和查询公网 IP 情报，绝不连接节点端口。
- 不实现 VPN、代理隧道或绕过系统网络策略。出口 IP 检测走设备当前系统路由。
- 原始订阅正文不写入项目数据；原生客户端保存 URL 时使用系统凭据库。油猴版使用用户口令派生的 AES-GCM 密钥，口令不保存。
- 第三方 IP 情报会记录来源、UTC 查询时间、耗时和错误，但任何数据库都无法保证绝对实时或绝对准确。
