# IPBatchInspector 5

IPBatchInspector 是一套证据优先、跨平台的 IP 批量情报与订阅检查工具。一个仓库同时提供 Android、iOS、Windows、Linux、终端 CLI、Bash/PowerShell 脚本和 Tampermonkey/油猴版。5.0 增加“单 IP 详细调查”和“订阅真实测试”两个互相隔离的高级模式。

> 默认订阅体检仍然只解析、做系统 DNS 并查询节点 IP 情报，绝不连接节点端口。只有用户主动进入“真实测试”、确认影响范围并连接本机回环 Mihomo/Clash API 后，程序才会切换已有系统 VPN 的策略组并访问指定网址；项目不内置代理核心、不导入节点凭据、不自行建立隧道。

## 平台与入口

| 平台 | 入口 | 当前实现 |
| --- | --- | --- |
| Android 6+ | `apps/android` | 原生 Java；前台服务、详细调查、当前出口、订阅只解析及本机控制器真实测试 |
| iOS 16+ | `apps/ios` | 原生 SwiftUI；短时后台、详细调查、订阅只解析及本机控制器真实测试 |
| Windows 10/11 | `ipbatch-gui` | Python/Tk 原生桌面窗口；详细/真实模式；可由 CI 打包为单文件 EXE |
| Linux | `ipbatch-gui` | Python/Tk 桌面窗口；详细/真实模式；可由 CI 打包为可执行文件 |
| Terminal | `ipbatch` | 跨平台 CLI，支持表格、JSON、CSV |
| Script | `scripts/ipbatch.sh` / `scripts/ipbatch.ps1` | 无需先安装包，从源码直接运行 CLI |
| Tampermonkey | `userscript/IPBatchInspector.user.js` | 详细被动调查及本机控制器真实测试；不具备系统后台或实时 TLS 证书读取能力 |

## 正式下载与安装

进入 [GitHub Releases](https://github.com/zizegak916-glitch/0612/releases/latest) 下载，并用同一页面的 `SHA256SUMS.txt` 校验。文件名会明确区分正式签名、开发签名、未签名和模拟器产物。

| 目标 | 下载文件 | 安装方式 | 签名事实 |
| --- | --- | --- | --- |
| Windows x64 | `Windows-x64-Setup.exe` | 双击，按安装向导完成；也有 portable EXE | 可直接安装；未配置 Authenticode，SmartScreen 可能提示未知发布者 |
| Debian/Ubuntu x64 | `linux-x86_64.deb` | `sudo apt install ./IPBatchInspector-*.deb` | GitHub Actions 原生构建；DEB 当前未做发行版仓库签名 |
| 通用 Linux x64 | `linux-x86_64.tar.gz` | 解压后运行 `ipbatch-gui` 或 `ipbatch-cli` | 免安装包 |
| Android 6+ | `android-release.apk` 或 `android-debug.apk` | 允许浏览器/文件管理器安装未知应用后侧载 | `release` 仅在 GitHub Secrets 配置私有发布密钥时出现；`debug` 可安装但不是正式升级签名 |
| iOS 模拟器 | `iOS-Simulator.zip` | 拖入 Xcode Simulator | 不是 iPhone IPA；真机必须由 Apple 证书和描述文件签名 |
| Python/终端 | `.whl` | `python -m pip install ./ipbatch_inspector-*.whl` | 平台无关 Python 包 |
| 油猴 | `.user.js` | [直接打开主分支脚本](https://raw.githubusercontent.com/zizegak916-glitch/0612/main/userscript/IPBatchInspector.user.js)，在 Tampermonkey 中审查权限并安装 | 源码即安装内容，可自动检查更新 |

油猴版需要 `@connect *`，原因是订阅域名由用户输入，无法提前穷举；脚本不会自动扫描当前网页，只有打开面板并点击操作后才发请求。它支持常见 Clash/Stash/Sing-box/Surge/Loon 导入包装链接、通用 Base64、Clash YAML 及主流节点 URI；“支持”指提取节点主机与端口元数据，不表示实现协议握手。它默认拒绝字面私网/本机地址并通过 Cloudflare DoH 检查公共域名的 A/AAAA 记录；现代 Tampermonkey 还会手动处理重定向并逐跳审计，旧实现若无视手动跳转选项则会丢弃跨站最终响应。

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
ipbatch detail 1.1.1.1
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
ipbatch scan <IP/CIDR/文本...> [--json|--csv FILE] [--workers N] [--fresh] [--cache-ttl 秒]
ipbatch detail <一个公网IP> [--tls-port 443] [--fresh] [--no-domestic-fallback]
ipbatch subscription <HTTPS_URL> [--allow-private-subscription] [--list-nodes] [--json] [--fresh]
ipbatch ai [--json]
ipbatch realtest <HTTPS订阅> [--controller http://127.0.0.1:9090] [--group 策略组] [--node 精确节点名] [--targets all] [--custom-url HTTPS网址]
ipbatch formats
ipbatch monitor --config monitor.example.json [--once]
```

- `scan` 支持 IPv4、IPv6、CIDR（每个 CIDR 最多展开 4096 个地址）及包含 IP 的混合文本；单次最多 500 个唯一公网 IP。
- `subscription` 支持 Clash/Mihomo YAML、Base64 通用订阅、SS、SSR、VMess、VLESS、Trojan、Hysteria/Hysteria2/Hy2、TUIC、SOCKS4/5、HTTP(S) 代理 URI、`dialer-proxy` 链式引用与远程 `proxy-providers`。
- `sn://subscription` 会提取其中显式提供的 HTTP(S) 订阅地址；`fsl64`/`fslyaml` 首选格式失败时自动尝试另一格式，URL 查询串逐字保留，不重写 Token。
- 公网订阅强制 HTTPS。本机/局域网 HTTP 必须显式传入 `--allow-private-subscription`；解析出的私网、保留、CGNAT 或文档地址不会送到公网情报源。
- 原始订阅内容只在当前进程内存在。CLI 默认不打印原文，保存节点清单时也不输出密码、UUID、Token 或用户信息。
- `--fresh` 跳过缓存读取并用本次响应刷新缓存；`--cache-ttl` 可覆盖所有数据源 TTL。缓存保存公网 IP 情报，并对失败做 60 秒短期退避，不保存订阅 URL、订阅原文、节点凭据或 API Key。

### 单 IP 详细调查

`detail` 严格只接受一个公网 IP。它并发检索标准五源、完整 RDAP 登记实体、RIPEstat 网络/WHOIS/abuse/可见性、Shodan InternetDB、GreyNoise Community、PTR，并对明确列出的 TLS 端口（默认仅 443）抓取当前证书、指纹、主题、签发者、SAN、有效期、TLS 版本和密码套件。配置 `SHODAN_KEY`、`GREYNOISE_KEY`、`VIRUSTOTAL_KEY` 后会增加对应的已授权结果；密钥不写入报告。

这不是端口扫描：默认只有一个主动目标连接 `IP:443`。共享托管可能按 SNI 返回不同证书，因此程序只额外尝试“当前确实正向解析回该 IP”的 PTR/Shodan 主机名。第三方被动端口/CVE、风险或拥有者信息可能滞后；“所有公网信息”不存在可证明完备的集合，所以报告逐项列出实际查询源、时间、耗时、HTTP/网络失败和局限，绝不声称无遗漏。

### 订阅真实测试

真实测试需要设备上已经运行并由用户授权的 Clash/Mihomo 兼容客户端：

1. 在客户端开启 TUN/系统 VPN 与 External Controller，例如 `127.0.0.1:9090`；如有 Secret，通过密码框、`--controller-secret-file` 或临时环境变量 `MIHOMO_SECRET` 提供。
2. 在 IPBatchInspector 载入订阅。订阅只用于解析节点名称，再与控制器 `/proxies` 返回的节点求交集；程序不连接订阅中的服务器地址或端口。
3. 程序确认 `/configs` 的 TUN 已开启，记录测试前出口，逐节点执行 `PUT /proxies/{group}`，回读确认实际选择，然后访问 ChatGPT、Claude、Gemini、AI Studio、Grok、Perplexity、Copilot、DeepSeek、Qwen 的真实对话网址及用户自定义公网 HTTPS URL。
4. 匿名探针不发送登录 Cookie、账号、API Key、提示词或消息。登录跳转记为“已到达但需要认证”，只有响应明确出现国家/地区不可用语义时才标记 `geo_blocked`；403 会区分可能的 WAF/挑战，不能自动等同地区封锁。
5. 普通模式在 `finally` 中恢复原策略组节点。`--open-browser`/“打开对话页面”只允许一个精确节点，并故意保留该节点，让真实浏览器会话访问对话页；完成后由用户在代理客户端恢复。

控制器只允许 `http://127.0.0.1:端口`、`localhost` 或 `[::1]`，拒绝远程控制器、URL 用户信息和路径。切换策略组会短时影响使用同一系统 VPN 的其他应用；进程被强杀、控制器掉线或分流规则绕过测试进程时，结果和恢复均可能失败，报告会保留错误。

### Windows/Linux 后台运行

`monitor` 可按 JSON 配置持续执行出口、AI、IP、单 IP 详细调查、普通订阅检查，或用户明确配置的系统 VPN 真实测试；它原子更新 `latest.json`，保留最近历史并标记结果是否变化。配置文件不接受原始订阅 URL，只接受系统凭据库中的保存名称；Mihomo Secret 只能来自 `MIHOMO_SECRET` 或权限受控的 `controller_secret_file`，不会写入报告。后台真实测试禁止打开浏览器，并在每轮后恢复原节点。

- Linux：`scripts/install_service_linux.sh` 安装当前用户的 systemd 服务；无需 root，也不会取得额外网络权限。
- Windows：`scripts/install_service_windows.ps1` 注册当前用户登录后启动的计划任务。
- Linux DEB 同时安装 `ipbatch-monitor.service` 模板但不会擅自启用；先创建不含明文 URL 的配置，再由用户执行 `systemctl --user enable --now ipbatch-monitor`。
- Android：继续使用通知可见的前台服务。
- iOS：只申请系统允许的有限后台时间，不支持无限常驻。

后台真实测试配置示例（先执行 `ipbatch saved add primary --url-file subscription.txt`；Secret 放环境或权限为 600 的独立文件）：

```json
{
  "mode": "realtest",
  "saved_subscription": "primary",
  "controller": "http://127.0.0.1:9090",
  "controller_secret_file": "/absolute/private/path/mihomo-secret.txt",
  "group": "节点选择",
  "nodes": ["美国住宅-01"],
  "targets": ["chatgpt", "claude", "gemini", "aistudio"],
  "custom_urls": ["https://example.com/account"],
  "interval_seconds": 1800,
  "max_nodes": 5,
  "output_directory": "monitor-results"
}
```

配置中的 `nodes` 是精确显示名；留空会按控制器策略组顺序测试匹配节点，受 `max_nodes` 限制。后台模式固定 `open_browser=false`。

## 情报与真实性

默认源为 ipapi.is、proxycheck.io、GeoJS、RDAP 和 RIPEstat；可通过 `--sources` 选择。当至少两个全球地理源被请求但成功不足两个时，自动调用 CIP.cc HTTPS 国内备用页。该镜像标记为 `fallback-unverified`，不参与 high 置信度门槛，也不会覆盖已有权威登记/BGP 证据。每条结果记录查询目标、来源、UTC 时间、耗时、缓存命中与年龄、字段和错误。风险分始终保留来源，不把不同供应商的模型平均成伪精确总分。

国家、国家代码、ASN、地区、城市和组织按成功来源投票，`consensus` 保留获胜值、同意数和来源；`conflicts` 保存所有不一致值。代理/VPN/Tor/机房/滥用字段不再用“缺失即否”：`signals` 明确区分多源确认、单源报告、来源矛盾、明确未报和未知。`confidence` 只给可解释的 high/medium/low/none 等级，不给没有校准依据的综合小数分。

默认缓存按字段变化速度区分：RIPEstat 15 分钟，proxycheck/Ping0 30 分钟，ipapi.is 6 小时，GeoJS 24 小时，RDAP 7 天。RDAP.org 路径约每 1.05 秒最多启动一次请求，RIPEstat 全局最多 8 路并发；这是为了遵守公开服务限制并降低批量 429，而不是速度缺陷。详见 [`docs/DATA_SOURCES.md`](docs/DATA_SOURCES.md)。

工具能够保证的是“请求了谁、何时请求、得到了哪些字段、哪些请求失败”；不能保证第三方数据库绝对正确，也不能保证某个账号、模型或网站一定接受该 IP。城市定位和风险标签通常比 RDAP、BGP/RPKI 更易过期。

AI 检测分三类：

1. 当前设备直测公开网页/API 入口，只使用系统默认网络，不发送账号、Cookie、API Key 或提示词；预期的 400/401 鉴权错误表示入口有响应，不表示账号可用。
2. 对订阅节点只根据国家代码、官方地区快照和 IP 风险字段做推断，明确标注“未连接节点、非解锁实测”。
3. 用户显式启动的订阅真实测试，通过已有系统 VPN 逐节点访问真实对话 URL；它比地区推断更直接，但未登录匿名响应仍不能保证账号、付费权限、具体模型或发消息成功。

## 系统级/后台边界

- Android 使用正式前台服务，扫描、详细调查与真实测试离开页面后可继续，并显示系统通知；它不是 root、系统 UID 或 `/system/priv-app`。
- Windows/Linux 桌面窗口关闭后，当前交互任务会停止；已由用户显式安装的 systemd 用户服务或 Windows 计划任务独立运行。安装包不会在未告知的情况下自动启用后台监控。
- iOS 不允许普通第三方应用无限后台运行。应用在前台完成检测；系统只可能为短时任务提供有限后台时间。项目不会声称绕过 iOS 限制。
- 油猴脚本依赖浏览器标签页和扩展生命周期，不能替代系统服务；需要可靠后台监控时使用 Android 前台服务或 Windows/Linux 原生监控入口。
- 所有联网探针都使用当前进程的系统默认路由。真实测试只控制已经运行的 Mihomo/Clash 兼容系统 VPN；项目本身不携带代理协议实现，不能替代代理客户端。

## 构建

- Python/CLI：`python -m build`
- Windows/Linux GUI：见 [`docs/BUILDING.md`](docs/BUILDING.md)
- Android：`cd apps/android && ./build.sh`
- iOS：用 Xcode 打开 `apps/ios/IPBatchInspector.xcodeproj`，选择模拟器或签名设备构建。
- GitHub Actions：每次提交执行 Python、Android、Windows、Linux、iOS 和油猴静态/构建检查；新增 `.github/releases/v*.json` 发布清单后自动创建对应标签和 GitHub Release。
- 每次主分支 CI 同时提供 Android APK、Windows/Linux CLI 与桌面程序、iOS 模拟器包作为 Actions artifacts；iOS 真机安装仍需用户自己的 Apple 签名。

更完整的架构、安全边界和平台差异见 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)、[`SECURITY.md`](SECURITY.md) 与 [`PRIVACY.md`](PRIVACY.md)。

## 开源许可

MIT License。第三方数据源各自的速率、授权和服务条款仍然适用。
