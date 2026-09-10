package com.fool.ipbatch;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TimeZone;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/** Bounded single-public-IP investigation with parallel, source-labelled evidence. */
public final class DetailedIpInvestigator {
    private static final int MAX_BODY = 512 * 1024;
    private static final String[][] PASSIVE = new String[][]{
            {"RDAP 当前登记/持有人", "https://rdap.org/ip/%s", "rdap"},
            {"RIPEstat 前缀/ASN", "https://stat.ripe.net/data/network-info/data.json?resource=%s", "network"},
            {"RIPEstat WHOIS", "https://stat.ripe.net/data/whois/data.json?resource=%s", "whois"},
            {"RIPEstat abuse 联系人", "https://stat.ripe.net/data/abuse-contact-finder/data.json?resource=%s", "abuse"},
            {"RIPEstat BGP 可见性", "https://stat.ripe.net/data/visibility/data.json?resource=%s", "visibility"},
            {"Shodan InternetDB 被动端口/CVE", "https://internetdb.shodan.io/%s", "internetdb"},
            {"GreyNoise Community 扫描活动", "https://api.greynoise.io/v3/community/%s", "greynoise"}
    };
    private static final String[] RDAP_DIRECT = new String[]{
            "https://rdap.arin.net/registry/ip/%s", "https://rdap.db.ripe.net/ip/%s",
            "https://rdap.apnic.net/ip/%s", "https://rdap.lacnic.net/rdap/ip/%s",
            "https://rdap.afrinic.net/rdap/ip/%s"
    };

    public String investigate(String rawIp, final ApiClient.Settings settings) throws Exception {
        final String ip = IpParser.normalize(rawIp == null ? "" : rawIp.trim());
        if (ip == null || !IpParser.isPublic(ip)) throw new Exception("详细调查只接受一个公网 IP；私网、保留、文档地址不会发送到外部来源");
        final int timeout = Math.max(3500, settings.timeoutMs);
        final long started = System.currentTimeMillis();
        ExecutorService executor = Executors.newFixedThreadPool(8);
        Future<IpResult> standardFuture = executor.submit(new Callable<IpResult>() {
            @Override public IpResult call() { return new ApiClient().scan(ip, settings); }
        });
        final String encoded = URLEncoder.encode(ip, "UTF-8");
        List<Future<Observation>> futures = new ArrayList<>();
        for (final String[] source : PASSIVE) futures.add(executor.submit(new Callable<Observation>() {
            @Override public Observation call() { return fetch(source, encoded, timeout); }
        }));

        StringBuilder out = new StringBuilder();
        out.append("单 IP 详细调查\n目标：").append(ip).append("\n查询时间：").append(utc(new Date()))
                .append("\n模式：实时请求；并行数据源；失败源重试 1 次；只主动连接目标 443/TCP。\n\n【标准多源结论】\n");
        IpResult standard;
        try { standard = standardFuture.get(); }
        catch (Exception failure) { standard = new IpResult(ip); standard.status = "失败"; standard.errors.add("标准扫描：" + safe(failure)); }
        appendStandard(out, standard);

        out.append("\n\n【公网登记、路由与风险明细】");
        List<Observation> observations = new ArrayList<>(); int failures = 0; Set<String> hostnames = new LinkedHashSet<>();
        for (Future<Observation> future : futures) {
            Observation item;
            try { item = future.get(); } catch (Exception failure) { item = Observation.failure("未知来源", safe(failure), 0, 0); }
            observations.add(item); if (!item.success) failures++;
            out.append("\n\n-- ").append(item.name).append(" --\n").append(item.summary);
            if ("internetdb".equals(item.kind) && item.success) collectHostnames(item.body, hostnames);
        }
        executor.shutdownNow();

        String ptr = verifiedPtr(ip); if (!ptr.isEmpty()) hostnames.add(ptr);
        out.append("\n\n【反向 DNS 与当前正向校验】\nPTR：").append(ptr.isEmpty() ? "未找到，或当前 A/AAAA 已不再指向目标 IP" : ptr);
        out.append("\nTLS SNI 候选：").append(hostnames.isEmpty() ? "无" : IpResult.join(new ArrayList<String>(hostnames), "、"));

        out.append("\n\n【主动 TLS 443 观测】\n");
        List<String> verifiedNames = new ArrayList<>(); for (String name : hostnames) if (pointsTo(name, ip) && verifiedNames.size() < 3) verifiedNames.add(name);
        if (verifiedNames.isEmpty()) {
            try { out.append(certificate(ip, 443, "", timeout)); }
            catch (Exception failure) { out.append("无 SNI TLS 失败：").append(safe(failure)); }
        } else {
            for (String name : verifiedNames) {
                try { out.append(certificate(ip, 443, name, timeout)); }
                catch (Exception failure) { out.append("SNI ").append(name).append(" 失败：").append(safe(failure)); }
                out.append("\n");
            }
        }

        if (failures >= 3) {
            out.append("\n【境内辅助源（非官方镜像；仅在核心源大量失败时调用）】\n");
            appendAuxiliary(out, "百度智能云 IP 地理辅助", "https://qifu-api.baidubce.com/ip/geo/v1/district?ip=" + encoded, ip, timeout);
            appendAuxiliary(out, "CIP.cc 页面辅助", "https://www.cip.cc/" + encoded, ip, timeout);
        } else {
            out.append("\n【境内辅助源】\n核心被动源失败少于 3 个，本次未调用；这些站点不是 RDAP/RIPE/Shodan 的官方镜像。\n");
        }

        out.append("\n【数据源健康矩阵】\n来源 | 成功 | HTTP | 最终主机 | 尝试 | 耗时 | 观测时间\n");
        for (Observation item : observations) out.append(item.name).append(" | ").append(item.success ? "是" : "否").append(" | ")
                .append(item.code <= 0 ? "-" : item.code).append(" | ").append(item.finalHost).append(" | ").append(item.attempts)
                .append(" | ").append(item.durationMs).append(" ms | ").append(utc(new Date(item.observedAt))).append("\n");

        out.append("\n【真实性、时效与能力边界】\n")
                .append("1. ‘当前持有人’来自本次 RDAP 响应中的网络对象和实体角色，不把注册国家冒充物理位置。\n")
                .append("2. Shodan/GreyNoise/CVE/端口是第三方最近收录，不代表此刻仍开放，也不代表完整扫描结果。\n")
                .append("3. TLS 只连接 443，优先使用当下仍正向指向该 IP 的 PTR/InternetDB 主机名作 SNI；未扫描其他端口。\n")
                .append("4. 证书抓取关闭信任判定仅为读取对端公开字段，不把它当作安全背书。\n")
                .append("5. 没有任何工具能保证穷尽‘所有公网信息’或永久真实；本报告只对列出的 URL、HTTP 状态和观测时间负责。\n")
                .append("总耗时：").append(System.currentTimeMillis() - started).append(" ms");
        return out.toString();
    }

    private Observation fetch(String[] source, String encoded, int timeout) {
        long started = System.currentTimeMillis(); HttpResult response = null; Exception last = null; int attempts = 0;
        for (int attempt = 1; attempt <= 2; attempt++) {
            attempts = attempt;
            try {
                response = get(String.format(Locale.ROOT, source[1], encoded), timeout);
                if (response.code == 429 || response.code >= 500) throw new Exception("HTTP " + response.code);
                if (response.code >= 400 && response.code != 404) throw new Exception("HTTP " + response.code);
                break;
            } catch (Exception failure) { last = failure; if (attempt == 1) try { Thread.sleep(250L); } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); } }
        }
        // rdap.org is a bootstrap proxy, not the authority itself.  A timeout,
        // rate limit, server error or stale 404 must all fall through to the
        // five RIR services instead of being mistaken for a final answer.
        if ((response == null || response.code < 200 || response.code >= 300) && "rdap".equals(source[2])) {
            for (String address : RDAP_DIRECT) try {
                attempts++; HttpResult candidate = get(String.format(Locale.ROOT, address, encoded), timeout);
                if (candidate.code >= 200 && candidate.code < 300) { response = candidate; break; }
                last = new Exception("HTTP " + candidate.code + " from " + candidate.finalHost);
            } catch (Exception failure) { last = failure; }
        }
        long duration = System.currentTimeMillis() - started;
        if (response == null) return Observation.failure(source[0], safe(last), attempts, duration);
        boolean noRecord = response.code == 404
                && ("internetdb".equals(source[2]) || "greynoise".equals(source[2]));
        boolean success = (response.code >= 200 && response.code < 300) || noRecord;
        String summary = noRecord
                ? "上游已响应但当前无收录（HTTP 404）；这不等于安全，也不属于网络请求失败。"
                : success ? summarize(source[2], response.body)
                : "请求失败：HTTP " + response.code + "\n" + clip(response.body, 600);
        return new Observation(source[0], source[2], response.body, summary, success, response.code, response.finalHost, attempts, duration, System.currentTimeMillis());
    }

    private String summarize(String kind, String body) {
        try {
            JSONObject root = new JSONObject(body);
            if ("rdap".equals(kind)) return summarizeRdap(root);
            if ("internetdb".equals(kind)) return "主机名：" + root.optJSONArray("hostnames") + "\n端口（被动收录）：" + root.optJSONArray("ports")
                    + "\nCPE：" + root.optJSONArray("cpes") + "\n漏洞标识：" + root.optJSONArray("vulns") + "\n标签：" + root.optJSONArray("tags");
            if ("greynoise".equals(kind)) return "noise=" + root.opt("noise") + "；riot=" + root.opt("riot")
                    + "；classification=" + root.optString("classification", "未知") + "；name=" + root.optString("name", "")
                    + "；last_seen=" + root.optString("last_seen", "未提供") + "\nmessage=" + root.optString("message", "");
            JSONObject data = root.optJSONObject("data"); if (data == null) return clip(root.toString(2), 9000);
            if ("network".equals(kind)) return "前缀：" + data.optString("prefix", "未提供") + "\n起源 ASN：" + data.optJSONArray("asns");
            if ("abuse".equals(kind)) return "abuse 联系方式：" + data.optJSONArray("abuse_contacts") + "\n权威结果时间：" + root.optString("data_call_status", "");
            if ("visibility".equals(kind)) return "可见性摘要：" + clip(data.toString(2), 6000);
            if ("whois".equals(kind)) return summarizeWhois(data.optJSONArray("records"));
            return clip(data.toString(2), 9000);
        } catch (Exception failure) { return "返回不是可结构化 JSON：" + clip(body, 1800); }
    }

    private String summarizeRdap(JSONObject root) {
        StringBuilder out = new StringBuilder();
        out.append("对象：").append(root.optString("name", root.optString("handle", "未提供")))
                .append("；类型：").append(root.optString("type", "未提供"))
                .append("\n范围：").append(root.optString("startAddress", "?")).append(" - ").append(root.optString("endAddress", "?"))
                .append("；登记国家：").append(root.optString("country", "未提供"))
                .append("\nport43：").append(root.optString("port43", "未提供"));
        JSONArray events = root.optJSONArray("events"); if (events != null) for (int i = 0; i < Math.min(12, events.length()); i++) {
            JSONObject event = events.optJSONObject(i); if (event != null) out.append("\n事件：").append(event.optString("eventAction", ""))
                    .append(" = ").append(event.optString("eventDate", ""));
        }
        JSONArray entities = root.optJSONArray("entities"); if (entities != null) for (int i = 0; i < Math.min(20, entities.length()); i++) {
            JSONObject entity = entities.optJSONObject(i); if (entity == null) continue;
            out.append("\n实体：").append(entity.optString("handle", "未命名")).append("；角色：").append(entity.optJSONArray("roles"));
            JSONArray card = entity.optJSONArray("vcardArray"); if (card != null && card.length() > 1) out.append("；公开联系：").append(vcard(card.optJSONArray(1)));
        }
        return clip(out.toString(), 12000);
    }

    private String vcard(JSONArray rows) {
        if (rows == null) return "未提供"; StringBuilder out = new StringBuilder();
        for (int i = 0; i < rows.length(); i++) { JSONArray row = rows.optJSONArray(i); if (row == null || row.length() < 4) continue;
            String key = row.optString(0, ""); if (!"fn".equals(key) && !"org".equals(key) && !"email".equals(key) && !"tel".equals(key)) continue;
            if (out.length() > 0) out.append("，"); out.append(key).append("=").append(clip(String.valueOf(row.opt(3)), 180));
        }
        return out.length() == 0 ? "未提供" : out.toString();
    }

    private String summarizeWhois(JSONArray groups) {
        if (groups == null) return "WHOIS 无 records"; StringBuilder out = new StringBuilder(); int count = 0;
        for (int i = 0; i < groups.length() && count < 80; i++) { JSONArray rows = groups.optJSONArray(i); if (rows == null) continue;
            for (int j = 0; j < rows.length() && count < 80; j++) { JSONObject row = rows.optJSONObject(j); if (row == null) continue;
                String key = row.optString("key", ""); String value = row.optString("value", "");
                if (key.isEmpty() || value.isEmpty()) continue; if (out.length() > 0) out.append("\n"); out.append(key).append(": ").append(clip(value, 300)); count++;
            }
        }
        return out.length() == 0 ? "WHOIS records 为空" : out.toString();
    }

    private void appendStandard(StringBuilder out, IpResult standard) {
        out.append("状态：").append(standard.status).append("；置信度：").append(standard.confidence)
                .append("\n位置：").append(standard.locationText()).append("\n网络：").append(standard.networkText())
                .append("\n风险：").append(standard.flagsText()).append("\n来源证据：").append(IpResult.join(standard.sourceEvidence, "；"));
        if (!standard.conflicts.isEmpty()) out.append("\n冲突：").append(IpResult.join(standard.conflicts, "；"));
        if (!standard.errors.isEmpty()) out.append("\n失败源：").append(IpResult.join(standard.errors, "；"));
    }

    private void appendAuxiliary(StringBuilder out, String name, String url, String expectedIp, int timeout) {
        try {
            HttpResult result = get(url, timeout);
            if (result.code < 200 || result.code >= 300) throw new Exception("HTTP " + result.code);
            String rendered = result.body.replaceAll("(?is)<[^>]+>", " ").replaceAll("\\s+", " ");
            if (!rendered.contains(expectedIp)) throw new Exception("响应未回显目标 IP，拒绝采信");
            out.append(name).append("：HTTP ").append(result.code).append("；")
                    .append(clip(rendered, 1500)).append("\n");
        }
        catch (Exception failure) { out.append(name).append("：失败；").append(safe(failure)).append("\n"); }
    }

    private HttpResult get(String address, int timeout) throws Exception {
        URL current = new URL(address);
        for (int hop = 0; hop <= 4; hop++) {
            validateHttpsPublic(current); HttpURLConnection connection = (HttpURLConnection) current.openConnection();
            try {
                connection.setConnectTimeout(timeout); connection.setReadTimeout(timeout); connection.setRequestMethod("GET");
                connection.setInstanceFollowRedirects(false); connection.setUseCaches(false);
                connection.setRequestProperty("Accept", "application/rdap+json,application/json,text/html;q=0.5,*/*;q=0.2");
                connection.setRequestProperty("Accept-Encoding", "identity"); connection.setRequestProperty("User-Agent", "IPBatchInspector/6.0.0-alpha.2 Android detailed mode");
                int code = connection.getResponseCode();
                if (code >= 300 && code < 400) {
                    String location = connection.getHeaderField("Location"); if (location == null || location.trim().isEmpty()) throw new Exception("HTTPS 跳转缺少 Location");
                    current = new URL(current, location); continue;
                }
                InputStream input = code >= 200 && code < 400 ? connection.getInputStream() : connection.getErrorStream();
                return new HttpResult(code, read(input), current.getHost());
            } finally { connection.disconnect(); }
        }
        throw new Exception("HTTPS 跳转超过 4 次");
    }

    private void validateHttpsPublic(URL url) throws Exception {
        if (!"https".equalsIgnoreCase(url.getProtocol()) || url.getUserInfo() != null) throw new Exception("调查源/跳转必须是无用户信息的 HTTPS");
        String host = url.getHost().toLowerCase(Locale.ROOT);
        boolean allowed = false; for (String suffix : new String[]{"rdap.org", "arin.net", "ripe.net", "apnic.net", "lacnic.net", "afrinic.net", "shodan.io", "greynoise.io", "baidubce.com", "cip.cc"})
            if (host.equals(suffix) || host.endsWith("." + suffix)) { allowed = true; break; }
        if (!allowed) throw new Exception("拒绝调查源跳转到未授权主机：" + host);
        for (InetAddress address : InetAddress.getAllByName(host)) {
            String ip = IpParser.normalize(address.getHostAddress()); if (ip == null || !IpParser.isPublic(ip)) throw new Exception("调查源解析到私网/保留地址：" + host);
        }
    }

    private String certificate(String ip, int port, String sni, int timeout) throws Exception {
        final X509TrustManager trust = new X509TrustManager() {
            @Override public void checkClientTrusted(X509Certificate[] chain, String authType) { }
            @Override public void checkServerTrusted(X509Certificate[] chain, String authType) { }
            @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        };
        SSLContext context = SSLContext.getInstance("TLS"); context.init(null, new TrustManager[]{trust}, new SecureRandom());
        Socket raw = new Socket(); raw.connect(new InetSocketAddress(ip, port), timeout); raw.setSoTimeout(timeout);
        SSLSocket socket = (SSLSocket) context.getSocketFactory().createSocket(raw, sni.isEmpty() ? ip : sni, port, true);
        try {
            socket.startHandshake(); java.security.cert.Certificate[] chain = socket.getSession().getPeerCertificates();
            if (chain.length == 0 || !(chain[0] instanceof X509Certificate)) throw new SSLPeerUnverifiedException("对端没有 X.509 证书");
            X509Certificate cert = (X509Certificate) chain[0]; StringBuilder out = new StringBuilder();
            out.append("连接 ").append(ip).append(":").append(port).append("；SNI=").append(sni.isEmpty() ? "IP（无已验证主机名）" : sni)
                    .append("；TLS=").append(socket.getSession().getProtocol()).append("；套件=").append(socket.getSession().getCipherSuite())
                    .append("\nSubject：").append(cert.getSubjectX500Principal().getName()).append("\nIssuer：").append(cert.getIssuerX500Principal().getName())
                    .append("\n有效期：").append(utc(cert.getNotBefore())).append(" → ").append(utc(cert.getNotAfter()))
                    .append("\nSHA-256：").append(hex(MessageDigest.getInstance("SHA-256").digest(cert.getEncoded()))).append("\nSAN：");
            Collection<List<?>> sans = cert.getSubjectAlternativeNames(); if (sans == null || sans.isEmpty()) out.append("无"); else {
                int count = 0; for (List<?> item : sans) { if (count++ >= 100) { out.append("…"); break; } if (count > 1) out.append("，"); out.append(item.size() > 1 ? item.get(1) : item); }
            }
            out.append("\n证书链长度：").append(chain.length).append("；信任校验：关闭（仅观测字段）"); return out.toString();
        } finally { try { socket.close(); } catch (Exception ignored) { } }
    }

    private String verifiedPtr(String ip) { try { String name = InetAddress.getByName(ip).getCanonicalHostName(); return name.equals(ip) || !pointsTo(name, ip) ? "" : name; } catch (Exception ignored) { return ""; } }
    private boolean pointsTo(String name, String ip) { try { for (InetAddress address : InetAddress.getAllByName(name)) if (ip.equals(IpParser.normalize(address.getHostAddress()))) return true; } catch (Exception ignored) { } return false; }
    private void collectHostnames(String body, Set<String> output) { try { JSONArray values = new JSONObject(body).optJSONArray("hostnames"); if (values != null) for (int i = 0; i < Math.min(20, values.length()); i++) { String value = values.optString(i, "").trim(); if (!value.isEmpty()) output.add(value); } } catch (Exception ignored) { } }
    private String read(InputStream input) throws Exception { if (input == null) return ""; try (InputStream in = input; ByteArrayOutputStream out = new ByteArrayOutputStream()) { byte[] buffer = new byte[8192]; int read; while ((read = in.read(buffer)) >= 0) { if (read == 0) continue; if (out.size() + read > MAX_BODY) throw new Exception("返回超过 512 KiB"); out.write(buffer, 0, read); } return new String(out.toByteArray(), StandardCharsets.UTF_8); } }
    private static String utc(Date date) { SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.ROOT); format.setTimeZone(TimeZone.getTimeZone("UTC")); return format.format(date); }
    private static String hex(byte[] bytes) { StringBuilder out = new StringBuilder(); for (byte b : bytes) out.append(String.format(Locale.ROOT, "%02x", b & 255)); return out.toString(); }
    private static String clip(String value, int max) { return value == null ? "" : value.length() <= max ? value : value.substring(0, max) + " [已截断]"; }
    private static String safe(Throwable error) { if (error == null) return "未知错误"; String value = error.getMessage(); return clip(value == null || value.trim().isEmpty() ? error.getClass().getSimpleName() : value.replace('\n', ' '), 300); }

    private static final class HttpResult { final int code; final String body, finalHost; HttpResult(int code, String body, String finalHost) { this.code = code; this.body = body; this.finalHost = finalHost; } }
    private static final class Observation {
        final String name, kind, body, summary, finalHost; final boolean success; final int code, attempts; final long durationMs, observedAt;
        Observation(String name, String kind, String body, String summary, boolean success, int code, String finalHost, int attempts, long durationMs, long observedAt) {
            this.name = name; this.kind = kind; this.body = body; this.summary = summary; this.success = success; this.code = code;
            this.finalHost = finalHost == null ? "" : finalHost; this.attempts = attempts; this.durationMs = durationMs; this.observedAt = observedAt;
        }
        static Observation failure(String name, String message, int attempts, long duration) {
            return new Observation(name, "", "", "失败：" + message, false, 0, "", attempts, duration, System.currentTimeMillis());
        }
    }
}
