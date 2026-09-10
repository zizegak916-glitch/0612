# IPBatchInspector 6.0.0-alpha.2 · 纯调查版

IPBatchInspector 是一套证据优先的 IP 批量情报、单 IP 深度调查、当前出口观测和只读订阅解析工具。仓库同时提供 Android、iOS、Windows、Linux、终端 CLI、Bash/PowerShell 脚本和 Tampermonkey/油猴版。

> 6.0.0-alpha.2 已删除上一测试版中的 VPN、libbox、Mihomo 控制器、节点切换和“订阅真实测试”。本项目不会连接订阅节点、不会建立隧道、不会改变设备路由，也不能用来绕过网络限制。alpha.1 的 VPN 实验版已撤回，不应继续安装或分发。

## 能做什么

- 批量调查 IPv4、IPv6、CIDR 和混合文本中的公网 IP；拒绝把私网、保留、CGNAT、文档地址发给第三方情报源。
- 直接识别“本应用进程当前默认路由”看到的出口 IPv4/IPv6，并保留多个回显源的分歧。
- 对一个公网 IP 做详细调查：多源地理/ASN/机构、RDAP 当前登记、RIPEstat 路由与 WHOIS、滥用联系人、PTR、Shodan InternetDB、GreyNoise，以及显式端口上的实时 TLS 证书观察。
- 下载并解析订阅文本，识别常见 Clash/Mihomo YAML、Base64、代理 URI、链式引用和远程 provider；保存订阅 URL 时使用平台安全存储。
- 用当前系统路由匿名访问多个 AI 公共入口，记录时间、HTTP 状态、跳转、拒绝/挑战和网络错误；不登录、不发消息、不输出“支持/不支持”结论。
- Android 通过通知可见的前台服务继续用户主动发起的扫描；Windows/Linux 可显式安装用户级定时监控。

## 不能做什么

- 不实现代理协议，不连接节点端口，不做握手、测速、解锁测试、流媒体测试或出口验证。
- 不包含 Android `VpnService`、iOS Network Extension、TUN、系统代理修改、root、系统 UID 或特权应用能力。
- 不可能从普通订阅文本看见中转服务器、链式落地、域名后动态选择的最终出口或服务端 NAT 出口。
- 不能凭 IP 的国家/地区、ASN、机房或代理标签判断 ChatGPT、Claude、Gemini 等是否可用。
- 不能保证第三方数据库绝对正确或实时，也不能声称收集了“互联网上所有信息”。报告能保证的是：明确记录查询源、查询时间、返回字段、冲突、错误和已知边界。

## 订阅到底能调查到什么

解析协议与实际连接协议是两件不同的事。本项目只解析节点元数据，且只把 `server` 字段中直接写出的公网 IP 送去 IP 情报查询。

| 订阅内容 | 分类 | 是否做 IP 情报 | 真实含义 |
| --- | --- | ---: | --- |
| `server: 8.8.8.8` 一类公网 IP 字面量 | 原文直露 IP | 是 | 调查的是订阅原文写出的地址；仍不证明它是最终出口 |
| `server: edge.example.com` | 仅域名节点 | 否 | 系统 DNS 的 A/AAAA 仅列为“DNS 入口观察”，绝不冒充节点 IP 或出口 IP |
| `server: 192.168.1.2`、环回、CGNAT、保留地址 | 非公网字面量 | 否 | 本地拦截，不外发给公共情报源 |
| `dialer-proxy`、`detour`、relay/链式代理 | 链式引用 | 仅调查其中直接暴露的公网 IP | 中转顺序和最终落地出口不能由静态文本证明 |
| 远程 `proxy-providers` | 额外订阅文档 | 下载后执行相同解析与安全校验 | 仍然只调查 provider 文本中直露的公网 IP |
| 加密/私有格式、脚本生成配置、服务端动态路由 | 不透明输入 | 否 | 无法安全解析时明确报告不支持，不猜测结果 |

因此，一份有 100 个域名节点的订阅可以得到 100 个节点元数据和若干 DNS 观察，但“可证明的真实流量出口”仍是 0。若订阅原文没有直接暴露公网 IP，应用会明确显示“没有可调查 IP”，而不是调查 CDN/DNS 地址后伪装成节点结果。

## AI 信息如何判断

AI 结果拆成互不替代的四类证据：

| 证据 | 本项目是否获取 | 可以说明 | 不能说明 |
| --- | ---: | --- | --- |
| 当前路由匿名 HTTP 观察 | 是 | 此设备/进程此刻是否收到入口响应、跳转、鉴权响应、挑战或网络错误 | 登录后对话、账号状态、具体模型、订阅权益和长期可用性 |
| IP 地理/ASN/风险情报 | 是 | 数据源如何描述该 IP | 某 AI 服务一定允许或拒绝该 IP |
| 服务商官方政策页面 | 仅链接并标注核对日期 | 页面声明的产品范围与地区政策 | 另一个产品的政策、网页实际可达性或个人账号结果 |
| 登录后的真实对话 | 否 | 只有用户在自己的浏览器/应用中才能验证 | 本项目不读取 Cookie、不登录、不发送提示词 |

特别说明：香港 IP 不会因为 `country_code=HK` 被判为“GPT 不支持”。截至 2026-09-09 核对的 [OpenAI API 支持国家与地区页面](https://developers.openai.com/api/docs/supported-countries)只描述 API 服务政策，不能拿来替代 ChatGPT 网页实测，更不能覆盖用户在香港实际可用的事实。代码因此不再维护国家白名单/黑名单，也不把 403 自动解释为地区封锁。

AI 入口状态使用中性事实名称，例如：`已收到入口响应`、`已收到跳转响应`、`已收到鉴权响应`、`观察到拒绝/挑战`、`传输失败`。只有响应正文明确出现地区不可用语义时，才记录“本次响应观察到地区提示”，仍不升级为永久国家结论。

## 单 IP 详细调查

`detail` 一次严格只接收一个公网 IP，并行执行以下调查：

- 标准五源：ipapi.is、proxycheck.io、GeoJS、RDAP、RIPEstat；Ping0 仅在提供 `PING0_KEY` 时启用。
- RDAP：地址范围、句柄、名称、状态、事件、父级句柄、公开登记实体/角色/联系人。
- RIPEstat：覆盖前缀、起源 ASN、WHOIS/IRR、滥用联系人、RIS 可见性和返回时间。
- Shodan InternetDB：被动观察到的端口、主机名、CPE、CVE 和标签；不是主动端口扫描。
- GreyNoise Community：噪声/扫描/RIOT 分类与时间；无记录不等于安全。
- PTR/rDNS：当前反向解析结果。
- TLS：默认只连接目标 `IP:443`，记录叶证书主题、签发者、SAN、序列号、指纹、有效期、TLS 版本和密码套件。共享托管在无正确 SNI 时可能返回默认站点证书。
- 国内辅助源：全球地理源成功不足两个时请求 CIP.cc HTTPS 页面；Android 详细模式在多个被动源失败时还会尝试百度智能云 IP 地理接口。两者都是低信任辅助源，不是上述数据库的镜像，不覆盖权威登记/BGP 证据，也不能单独把置信度提高到 high。响应未回显目标 IP 时拒绝采信。

可选的 `SHODAN_KEY`、`GREYNOISE_KEY`、`VIRUSTOTAL_KEY` 会增加对应授权数据；密钥不会进入报告。详细调查不是完整互联网搜索，也不做端口范围扫描；被动端口/CVE、位置、风险和当前拥有者都可能存在滞后或归属语义差异。

## 平台与后台能力

| 平台 | 入口 | 后台事实 |
| --- | --- | --- |
| Android 7+ | `apps/android` | Java 原生应用；扫描、AI 入口观察和详细调查使用 `dataSync` 前台服务，必须显示通知。无 VPN/代理权限 |
| iOS 16+ | `apps/ios` | SwiftUI；只能请求系统允许的有限后台时间，不能无限常驻 |
| Windows 10/11 | `ipbatch-gui` / `ipbatch` | Tk 桌面与 CLI；Setup 可选注册当前用户登录计划任务运行 monitor |
| Linux | `ipbatch-gui` / `ipbatch` | Tk 桌面与 CLI；DEB 安装后运行 `ipbatch-enable-monitor` 可启用 systemd 用户服务 |
| Bash/PowerShell | `scripts/ipbatch.sh` / `scripts/ipbatch.ps1` | 调用同一 Python 核心 |
| Tampermonkey | `userscript/IPBatchInspector.user.js` | 依赖标签页与扩展生命周期，不是系统后台服务；浏览器也无法直接读取目标 IP 的实时 TLS 握手证书 |

“系统级工具”在这里仅指使用操作系统提供的前台服务、凭据库、Keychain、systemd 用户服务或计划任务集成；它不是 Android/iOS 特权系统应用。Android 申请的权限只有网络、网络状态、前台数据同步、通知和唤醒锁。拒绝通知权限会影响后台任务的可见性/启动条件，不会凭空赋予或移除 VPN 能力，因为项目根本不包含 VPN 服务。

## 安装和运行

正式构建由 [GitHub Actions](https://github.com/zizegak916-glitch/0612/actions) 产生；已发布版本见 [GitHub Releases](https://github.com/zizegak916-glitch/0612/releases)。安装前请核对版本名和 `SHA256SUMS.txt`。开发签名 APK 可侧载测试，但不是稳定发布签名；iOS 模拟器包也不是可直接安装到 iPhone 的 IPA。

Python 3.10+：

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
ipbatch ai --json
ipbatch-gui
```

Windows PowerShell 使用 `py` 和 `.\.venv\Scripts\Activate.ps1`。也可不安装直接运行 `./scripts/ipbatch.sh` 或 `.\scripts\ipbatch.ps1`。

## CLI 命令

```text
ipbatch exit [--json]
ipbatch scan <IP/CIDR/文本...> [--json] [--csv FILE] [--workers N] [--fresh]
ipbatch detail <一个公网IP> [--tls-port PORT] [--fresh] [--no-domestic-fallback]
ipbatch subscription [URL|--url-file FILE|--saved NAME] [--list-nodes] [--json] [--fresh]
ipbatch ai [--json]
ipbatch formats
ipbatch saved add|list|delete ...
ipbatch monitor --config monitor.example.json [--once]
```

- `scan` 每个 CIDR 最多展开 4096 个地址，单次最多接受 500 个唯一公网 IP。
- 公网订阅默认强制 HTTPS；本机订阅管理器的 HTTP URL 必须显式使用 `--allow-private-subscription`。该选项只允许下载订阅，不会允许私网节点 IP 外发调查。
- `saved add` 把订阅 URL 保存到操作系统凭据库；原始订阅正文、节点 UUID/密码、Token 不写入扫描报告或 IP 情报缓存。
- `--fresh` 跳过本地证据缓存，但不能强迫上游数据库更新其底层数据。

Windows/Linux 的后台监控配置只接受无敏感信息的 JSON。订阅监控必须引用已经保存的名称：

```json
{
  "mode": "subscription",
  "saved_subscription": "primary",
  "interval_seconds": 1800,
  "history_limit": 10,
  "output_directory": "monitor-results"
}
```

`monitor` 还支持 `exit`、`ai`、`scan`、`detail`；不再接受 `realtest`。每轮原子更新 `latest.json` 并保留有限历史。Linux/Windows 服务安装方式见 [`docs/BUILDING.md`](docs/BUILDING.md)。

## 数据真实性与更新

每条源证据记录来源、UTC 查询时间、耗时、成功/失败、缓存命中与字段。合并国家/ASN/机构只是方便视图；原始来源冲突保留在 `conflicts` 中。风险分按供应商分别保留，不平均成虚假的统一分数。缺失的代理/VPN/Tor/机房字段是 `unknown`，不是 `false`。

默认客户端缓存 TTL 是项目的请求策略，不等于数据源更新周期：RIPEstat 15 分钟、proxycheck/Ping0 30 分钟、ipapi.is 6 小时、GeoJS 24 小时、RDAP 7 天。查询失败仅短暂退避 60 秒。具体来源、配额和边界见 [`docs/DATA_SOURCES.md`](docs/DATA_SOURCES.md)。

## 构建

- Python 包：`python -m build`
- Android：`cd apps/android && ./build.sh`；首次下载固定校验和的 Android 35 platform/build-tools、ECJ 与 JSON jar，不再下载 Go、NDK 或 libbox
- iOS：用 Xcode 16+ 打开 `apps/ios/IPBatchInspector.xcodeproj`
- 油猴静态检查：`node --check userscript/IPBatchInspector.user.js`
- 完整安装包说明：[`docs/BUILDING.md`](docs/BUILDING.md)

CI 的桌面产物必须包含 Windows Setup/便携 EXE、Linux DEB/便携 tar.gz；终端产物必须包含 wheel、源码包、脚本包和独立 `.user.js`。仅有裸二进制或“构建成功”日志不视为完成安装包交付。

架构和安全边界见 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)、[`SECURITY.md`](SECURITY.md) 与 [`PRIVACY.md`](PRIVACY.md)。项目采用 MIT License；第三方数据服务的条款、配额和授权仍分别适用。
