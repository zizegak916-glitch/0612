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
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/** Single-public-IP investigation. Passive databases are separated from the one explicit TLS connection. */
public final class DetailedIpInvestigator {
    private static final int MAX_BODY = 512 * 1024;
    private static final String[][] PASSIVE = new String[][]{
            {"RDAP 当前登记与持有人", "https://rdap.org/ip/%s"},
            {"RIPEstat 网络前缀/ASN", "https://stat.ripe.net/data/network-info/data.json?resource=%s"},
            {"RIPEstat WHOIS", "https://stat.ripe.net/data/whois/data.json?resource=%s"},
            {"RIPEstat abuse 联系人", "https://stat.ripe.net/data/abuse-contact-finder/data.json?resource=%s"},
            {"RIPEstat BGP 可见性", "https://stat.ripe.net/data/visibility/data.json?resource=%s"},
            {"Shodan InternetDB 被动端口/CVE", "https://internetdb.shodan.io/%s"},
            {"GreyNoise Community 扫描活动", "https://api.greynoise.io/v3/community/%s"}
    };

    public String investigate(String rawIp, ApiClient.Settings settings) throws Exception {
        String ip = IpParser.normalize(rawIp == null ? "" : rawIp.trim());
        if (ip == null || !IpParser.isPublic(ip)) {
            throw new Exception("详细调查只接受一个公网 IP；私网、保留、文档地址不会发送到外部来源");
        }
        int timeout = Math.max(3000, settings.timeoutMs);
        long started = System.currentTimeMillis();
        StringBuilder out = new StringBuilder();
        out.append("单 IP 详细调查\n目标：").append(ip)
                .append("\n查询时间：").append(utc(new Date()))
                .append("\n\n【标准多源结论】\n");
        IpResult standard = new ApiClient().scan(ip, settings);
        out.append("状态：").append(standard.status).append("；置信度：").append(standard.confidence)
                .append("\n位置：").append(standard.locationText())
                .append("\n网络：").append(standard.networkText())
                .append("\n风险：").append(standard.flagsText())
                .append("\n来源证据：").append(IpResult.join(standard.sourceEvidence, "；"));
        if (!standard.conflicts.isEmpty()) out.append("\n冲突：").append(IpResult.join(standard.conflicts, "；"));
        if (!standard.errors.isEmpty()) out.append("\n失败源：").append(IpResult.join(standard.errors, "；"));

        String encoded = URLEncoder.encode(ip, "UTF-8");
        out.append("\n\n【被动公网数据库】");
        for (String[] source : PASSIVE) {
            long sourceStarted = System.currentTimeMillis();
            try {
                HttpResult response = get(String.format(Locale.ROOT, source[1], encoded), timeout);
                out.append("\n\n-- ").append(source[0]).append(" · HTTP ").append(response.code)
                        .append(" · ").append(System.currentTimeMillis() - sourceStarted).append(" ms --\n")
                        .append(pretty(response.body));
            } catch (Exception failure) {
                out.append("\n\n-- ").append(source[0]).append(" · 失败 · ")
                        .append(safe(failure)).append(" --");
            }
        }

        String ptr = "";
        try {
            ptr = InetAddress.getByName(ip).getCanonicalHostName();
            if (ptr.equals(ip) || !pointsTo(ptr, ip)) ptr = "";
        } catch (Exception ignored) { }
        out.append("\n\n【反向 DNS】\nPTR：").append(ptr.isEmpty() ? "未找到或未正向验证回目标 IP" : ptr);

        out.append("\n\n【主动 TLS 证书抓取】\n");
        try { out.append(certificate(ip, 443, ptr, timeout)); }
        catch (Exception failure) { out.append("443/TCP TLS 失败：").append(safe(failure)); }

        int globalGeoSuccess = 0;
        for (String evidence : standard.sourceEvidence) {
            String lower = evidence.toLowerCase(Locale.ROOT);
            if (lower.contains("ipapi") || lower.contains("proxycheck") || lower.contains("geojs") || lower.contains("ping0")) globalGeoSuccess++;
        }
        if (globalGeoSuccess < 2) {
            out.append("\n\n【国内备用镜像（低可信）】\n");
            try {
                HttpResult mirror = get("https://www.cip.cc/" + encoded, timeout);
                String plain = mirror.body.replaceAll("(?is).*?<pre[^>]*>", "")
                        .replaceAll("(?is)</pre>.*", "").replaceAll("<[^>]+>", "").trim();
                out.append(plain).append("\n说明：非权威注册库，只作失败时的旁证，不提高高置信结论。");
            } catch (Exception failure) { out.append("失败：").append(safe(failure)); }
        } else out.append("\n\n【国内备用镜像】\n主要全球地理源已有至少两项成功，本次未调用。");

        out.append("\n\n【真实性与边界】\n")
                .append("1. 每项都显示实际来源、HTTP 状态或失败原因；第三方端口、CVE、风险记录可能过期或不完整。\n")
                .append("2. RDAP 的登记国家不等于服务器物理位置，abuse 联系人也可能缺失或失效。\n")
                .append("3. 主动网络动作仅为目标 443/TCP 的 TLS 握手；没有扫描端口、没有发送应用数据。\n")
                .append("4. 为了采集证书，TLS 抓取不据此信任 CA/主机名；证书字段是观测值，不是安全背书。\n")
                .append("5. 不存在能保证检索‘所有互联网信息’的有限数据集，本报告只对列出的来源和时间负责。\n")
                .append("总耗时：").append(System.currentTimeMillis() - started).append(" ms");
        return out.toString();
    }

    private String certificate(String ip, int port, String verifiedPtr, int timeout) throws Exception {
        final X509TrustManager trust = new X509TrustManager() {
            @Override public void checkClientTrusted(X509Certificate[] chain, String authType) { }
            @Override public void checkServerTrusted(X509Certificate[] chain, String authType) { }
            @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        };
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, new TrustManager[]{trust}, new SecureRandom());
        Socket raw = new Socket();
        raw.connect(new InetSocketAddress(ip, port), timeout);
        raw.setSoTimeout(timeout);
        SSLSocket socket = (SSLSocket) context.getSocketFactory().createSocket(raw, verifiedPtr.isEmpty() ? ip : verifiedPtr, port, true);
        try {
            socket.startHandshake();
            java.security.cert.Certificate[] chain = socket.getSession().getPeerCertificates();
            if (chain.length == 0 || !(chain[0] instanceof X509Certificate)) throw new SSLPeerUnverifiedException("对端没有 X.509 证书");
            X509Certificate cert = (X509Certificate) chain[0];
            StringBuilder out = new StringBuilder();
            out.append("连接：").append(ip).append(":").append(port)
                    .append("；SNI：").append(verifiedPtr.isEmpty() ? ip : verifiedPtr)
                    .append("；TLS：").append(socket.getSession().getProtocol())
                    .append("；套件：").append(socket.getSession().getCipherSuite())
                    .append("\nSubject：").append(cert.getSubjectX500Principal().getName())
                    .append("\nIssuer：").append(cert.getIssuerX500Principal().getName())
                    .append("\n序列号：").append(cert.getSerialNumber().toString(16))
                    .append("\n有效期：").append(utc(cert.getNotBefore())).append(" → ").append(utc(cert.getNotAfter()))
                    .append("\n签名算法：").append(cert.getSigAlgName())
                    .append("；公钥：").append(cert.getPublicKey().getAlgorithm())
                    .append("\nSHA-256：").append(hex(MessageDigest.getInstance("SHA-256").digest(cert.getEncoded())))
                    .append("\nSAN：");
            Collection<List<?>> sans = cert.getSubjectAlternativeNames();
            if (sans == null || sans.isEmpty()) out.append("无");
            else {
                int count = 0;
                for (List<?> item : sans) {
                    if (count++ >= 100) { out.append("…"); break; }
                    if (count > 1) out.append("，");
                    out.append(item.size() > 1 ? String.valueOf(item.get(1)) : String.valueOf(item));
                }
            }
            out.append("\n证书链长度：").append(chain.length).append("；采集校验：关闭（仅观测）");
            return out.toString();
        } finally { try { socket.close(); } catch (Exception ignored) { } }
    }

    private boolean pointsTo(String name, String ip) {
        try {
            for (InetAddress address : InetAddress.getAllByName(name)) {
                String value = IpParser.normalize(address.getHostAddress());
                if (ip.equals(value)) return true;
            }
        } catch (Exception ignored) { }
        return false;
    }

    private HttpResult get(String address, int timeout) throws Exception {
        HttpURLConnection connection = (HttpURLConnection) new URL(address).openConnection();
        try {
            connection.setConnectTimeout(timeout); connection.setReadTimeout(timeout);
            connection.setRequestMethod("GET"); connection.setInstanceFollowRedirects(false); connection.setUseCaches(false);
            connection.setRequestProperty("Accept", "application/json,text/html;q=0.7,*/*;q=0.5");
            connection.setRequestProperty("User-Agent", "IPBatchInspector/5.0 Android detailed mode");
            int code = connection.getResponseCode();
            InputStream input = code >= 200 && code < 400 ? connection.getInputStream() : connection.getErrorStream();
            String body = read(input);
            if (code >= 400 && code != 404) throw new Exception("HTTP " + code + " " + clip(body, 200));
            return new HttpResult(code, body);
        } finally { connection.disconnect(); }
    }

    private String read(InputStream input) throws Exception {
        if (input == null) return "";
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream(); byte[] buffer = new byte[8192]; int read;
            while ((read = input.read(buffer)) >= 0) {
                if (read == 0) continue;
                if (out.size() + read > MAX_BODY) throw new Exception("返回超过 512 KiB");
                out.write(buffer, 0, read);
            }
            return new String(out.toByteArray(), StandardCharsets.UTF_8);
        } finally { input.close(); }
    }

    private String pretty(String body) {
        try {
            String trimmed = body.trim();
            if (trimmed.startsWith("{")) return clip(new JSONObject(trimmed).toString(2), 48000);
            if (trimmed.startsWith("[")) return clip(new JSONArray(trimmed).toString(2), 48000);
        } catch (Exception ignored) { }
        return clip(body, 48000);
    }

    private static String utc(Date date) {
        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.ROOT);
        format.setTimeZone(TimeZone.getTimeZone("UTC")); return format.format(date);
    }
    private static String hex(byte[] bytes) { StringBuilder out = new StringBuilder(); for (byte b : bytes) out.append(String.format(Locale.ROOT, "%02x", b & 0xff)); return out.toString(); }
    private static String clip(String value, int max) { return value == null ? "" : value.length() <= max ? value : value.substring(0, max) + "\n[已截断]"; }
    private static String safe(Exception error) { String value = error.getMessage(); return clip(value == null ? error.getClass().getSimpleName() : value.replace('\n', ' '), 300); }
    private static final class HttpResult { final int code; final String body; HttpResult(int code, String body) { this.code = code; this.body = body; } }
}
