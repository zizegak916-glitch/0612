# IPBatchInspector 4

IPBatchInspector 是一套证据优先、跨平台的 IP 批量情报与订阅检查工具。一个仓库同时提供 Android、iOS、Windows、Linux、终端 CLI 和 Bash/PowerShell 脚本。

> 最重要的安全边界：订阅节点只解析、做系统 DNS 解析并查询节点 IP 情报。项目不会连接节点端口，不做 SS/SSR/VMess/VLESS/Trojan/Hysteria/TUIC 握手，不建立 VPN，不修改系统路由，也不把“地区支持”冒充为“节点解锁实测”。

## 平台与入口

| 平台 | 入口 | 当前实现 |
| --- | --- | --- |
| Android 6+ | `apps/android` | 原生 Java；前台服务、通知进度、当前出口、订阅解析、多源情报、AI 入口直测 |
| iOS 16+ | `apps/ios` | 原生 SwiftUI；当前出口、批量 IP、订阅只解析、AI 入口直测 |
| Windows 10/11 | `ipbatch-gui` | Python/Tk 原生桌面窗口；可由 CI 打包为单文件 EXE |
| Linux | `ipbatch-gui` | Python/Tk 桌面窗口；可由 CI 打包为可执行文件 |
| Terminal | `ipbatch` | 跨平台 CLI，支持表格、JSON、CSV |
| Script | `scripts/ipbatch.sh` / `scripts/ipbatch.ps1` | 无需先安装包，从源码直接运行 CLI |

## 快速开始

要求 Python 3.10+。扫描、解析和桌面 UI 仅使用标准库；若要在 Windows/Linux 保存订阅链接，安装 `.[secure-store]`，链接将交给系统凭据库而不是写入项目文件。

```bash
git clone https://github.com/zizegak916-glitch/0612.git
cd 0612
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[secure-store]'
ipbatch exit --json
ipbatch scan 1.1.1.1 8.8.8.8
ipbatch subscription 'https://example.com/subscription' --list-nodes
ipbatch ai
ipbatch-gui
```

Windows PowerShell：

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install -e .
ipbatch exit --json
ipbatch-gui
```

不安装也能运行：

```bash
./scripts/ipbatch.sh scan 1.1.1.1
```

```powershell
.\scripts\ipbatch.ps1 scan 1.1.1.1
```

## CLI

```text
ipbatch exit [--json]
ipbatch scan <IP/CIDR/文本...> [--json|--csv FILE] [--workers N]
ipbatch subscription <HTTPS_URL> [--allow-private-subscription] [--list-nodes] [--json]
ipbatch ai [--json]
ipbatch formats
ipbatch monitor --config monitor.example.json [--once]
```

- `scan` 支持 IPv4、IPv6、CIDR（每个 CIDR 最多展开 4096 个地址）及包含 IP 的混合文本；单次最多 500 个唯一公网 IP。
- `subscription` 支持 Clash/Mihomo YAML、Base64 通用订阅、SS、SSR、VMess、VLESS、Trojan、Hysteria/Hysteria2/Hy2、TUIC、SOCKS4/5、HTTP(S) 代理 URI、`dialer-proxy` 链式引用与远程 `proxy-providers`。
- `sn://subscription` 会提取其中显式提供的 HTTP(S) 订阅地址；`fsl64`/`fslyaml` 首选格式失败时自动尝试另一格式，URL 查询串逐字保留，不重写 Token。
- 公网订阅强制 HTTPS。本机/局域网 HTTP 必须显式传入 `--allow-private-subscription`；解析出的私网、保留、CGNAT 或文档地址不会送到公网情报源。
- 原始订阅内容只在当前进程内存在。CLI 默认不打印原文，保存节点清单时也不输出密码、UUID、Token 或用户信息。

### Windows/Linux 后台运行

`monitor` 可按 JSON 配置持续执行出口、AI、IP 或已安全保存的订阅检查，原子更新 `latest.json`，保留最近历史并标记结果是否变化。配置文件不接受原始订阅 URL，只接受系统凭据库中的保存名称。

- Linux：`scripts/install_service_linux.sh` 安装当前用户的 systemd 服务；无需 root，也不会取得额外网络权限。
- Windows：`scripts/install_service_windows.ps1` 注册当前用户登录后启动的计划任务。
- Android：继续使用通知可见的前台服务。
- iOS：只申请系统允许的有限后台时间，不支持无限常驻。

## 情报与真实性

默认源为 ipapi.is、proxycheck.io、GeoJS、RDAP 和 RIPEstat；可通过 `--sources` 选择。每条结果记录查询目标、来源、UTC 时间、耗时、字段和错误。风险分始终保留来源，不把不同供应商的模型平均成伪精确总分。

工具能够保证的是“请求了谁、何时请求、得到了哪些字段、哪些请求失败”；不能保证第三方数据库绝对正确，也不能保证某个账号、模型或网站一定接受该 IP。城市定位和风险标签通常比 RDAP、BGP/RPKI 更易过期。

AI 检测分两类：

1. 当前设备直测公开网页/API 入口，只使用系统默认网络，不发送账号、Cookie、API Key 或提示词；预期的 400/401 鉴权错误表示入口有响应，不表示账号可用。
2. 对订阅节点只根据国家代码、官方地区快照和 IP 风险字段做推断，明确标注“未连接节点、非解锁实测”。

## 系统级/后台边界

- Android 使用正式前台服务，任务离开页面后可继续，并显示系统通知；它不是 root、系统 UID 或 `/system/priv-app`。
- Windows/Linux 桌面端的任务在线程池中运行；关闭窗口即停止。可由用户自行配置系统服务，但项目默认不安装常驻服务。
- iOS 不允许普通第三方应用无限后台运行。应用在前台完成检测；系统只可能为短时任务提供有限后台时间。项目不会声称绕过 iOS 限制。
- 所有平台都使用当前进程的系统默认路由。若设备 VPN/系统代理包含本应用，检测到的是该路由出口；项目自身不提供“绕墙”或代理连接能力。

## 构建

- Python/CLI：`python -m build`
- Windows/Linux GUI：见 [`docs/BUILDING.md`](docs/BUILDING.md)
- Android：`cd apps/android && ./build.sh`
- iOS：用 Xcode 打开 `apps/ios/IPBatchInspector.xcodeproj`，选择模拟器或签名设备构建。
- GitHub Actions：每次提交执行 Python、Android、Windows 和 iOS 静态/构建检查；标签 `v*` 触发多平台产物工作流。
- 每次主分支 CI 同时提供 Android APK、Windows/Linux CLI 与桌面程序、iOS 模拟器包作为 Actions artifacts；iOS 真机安装仍需用户自己的 Apple 签名。

更完整的架构、安全边界和平台差异见 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)、[`SECURITY.md`](SECURITY.md) 与 [`PRIVACY.md`](PRIVACY.md)。

## 开源许可

MIT License。第三方数据源各自的速率、授权和服务条款仍然适用。
