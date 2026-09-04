# IPBatchInspector 4.1.0 — 更快、更准、更可审计

这是 4.0 的性能与证据质量升级，继续发布 Android、iOS 模拟器、Windows、Linux、Python/终端和油猴安装文件。

## 速度

- 同一个 IP 的独立数据源改为并行查询，不再等待五条串行网络链路；批量任务使用全局有界线程池。
- Python/Windows/Linux/CLI 增加分数据源成功结果缓存：RIPEstat 15 分钟、proxycheck/Ping0 30 分钟、ipapi.is 6 小时、GeoJS 24 小时、RDAP 7 天。
- `--fresh` 强制跳过读取缓存并用新响应更新缓存；`--cache-ttl 秒数` 可统一覆盖 TTL。
- Android 增加可关闭的 15 分钟成功结果缓存；设置中关闭即强制刷新。
- 油猴增加 15 分钟缓存及“强制刷新”开关；A/AAAA DNS、出口 IP 回显源、远程 proxy-provider 改为并发。
- 订阅内相同主机只做一次 DNS 查询；远程 proxy-provider 并发下载后仍按原顺序合并。
- iOS 的情报源、出口回显与 AI 公开入口改为并发，并对订阅 DNS 做 32 路有界分批。

## 准确性与真实性

- 国家、国家代码、ASN、城市、组织等字段使用来源投票；输出 `consensus` 的获胜值、同意来源和观测数。
- 不再隐藏来源分歧：`conflicts` 完整列出每个冲突值及其来源。
- 代理、VPN、Tor、机房、滥用信号区分 `confirmed`、`reported`、`disputed`、`not_reported` 和 `unknown`；缺字段不再等同于否。
- 可信度仅分 high/medium/low/none，并附可复核理由，不制造缺乏统计依据的综合精确分。
- proxycheck 请求加入 `seen=1`，保留其最后观测时间；供应商返回的风险分继续逐源保存，不跨模型平均。
- ipapi.is、GeoJS 和 proxycheck 回应会核对目标 IP；私网、保留、CGNAT、文档地址仍在本机拒绝，不发送到公网情报源。
- 当前出口由三个独立回显端点并发检测，保留全部观测及一致数量；IPv4/IPv6 分流造成的不同出口不会被静默抹掉。

## 限流与“及时”边界

- RDAP.org 官方公共引导服务按约 10 次/10 秒限制，因此所有客户端都对 RDAP 路径做约 1.05 秒间隔控制。
- RIPEstat 并发限制为 8，避免大批量任务触发上游拒绝。
- 匿名免费额度仍由各数据源决定；大批量查询可能出现 429。失败、耗时、缓存年龄和来源时间都会留在证据中。
- “强制刷新”只保证重新请求，不保证上游数据库刚刚更新；城市、风险标签、RDAP 注册和 BGP 观测具有不同更新时间。

## 安装事实

- Android 未配置仓库私有发布密钥时只发布可侧载的 debug 签名 APK；它不是应用商店正式签名。
- Windows 安装器当前无 Authenticode，SmartScreen 可能提示未知发布者。
- iOS 下载项为 CI 编译的模拟器应用，不是可直接安装到 iPhone 的 IPA。
- 所有文件附 `SHA256SUMS.txt`，应在安装前核对。

安全边界不变：订阅仅下载、解析、DNS 和查询公网 IP 情报；不连接节点端口，不建立代理/VPN，不修改系统路由。
