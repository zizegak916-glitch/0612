package com.fool.ipbatch;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TimeZone;

import javax.net.ssl.HttpsURLConnection;

final class RealRouteProbe {
    static final String[][] DEFAULTS = new String[][]{
            {"ChatGPT", "https://chatgpt.com/"}, {"Claude", "https://claude.ai/new"},
            {"Gemini", "https://gemini.google.com/app"}, {"AI Studio", "https://aistudio.google.com/app/prompts/new_chat"},
            {"Grok", "https://grok.com/"}, {"Perplexity", "https://www.perplexity.ai/"},
            {"Copilot", "https://copilot.microsoft.com/"}
    };

    static final class Target { final String name, url; Target(String name, String url) { this.name = name; this.url = url; } }

    List<Target> targets(String custom) throws Exception {
        List<Target> values = new ArrayList<>(); Set<String> seen = new LinkedHashSet<>();
        for (String[] row : DEFAULTS) add(values, seen, row[0], row[1]);
        if (custom != null) for (String raw : custom.split("[,\\n]")) {
            String value = raw.trim(); if (value.isEmpty()) continue;
            if (!value.contains("://")) value = "https://" + value;
            add(values, seen, "自定义", value);
            if (values.size() > 24) throw new Exception("网址总数最多 24 个");
        }
        return values;
    }

    String probe(Target target, int timeoutMs) {
        long started = System.currentTimeMillis(); String current = target.url;
        for (int hop = 0; hop <= 4; hop++) {
            HttpsURLConnection connection = null;
            try {
                URL url = validate(current); connection = (HttpsURLConnection) url.openConnection();
                connection.setConnectTimeout(timeoutMs); connection.setReadTimeout(timeoutMs);
                connection.setInstanceFollowRedirects(false); connection.setUseCaches(false); connection.setRequestMethod("GET");
                connection.setRequestProperty("Accept", "text/html,application/xhtml+xml,*/*;q=0.7");
                connection.setRequestProperty("Accept-Encoding", "identity");
                connection.setRequestProperty("User-Agent", "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/124 Mobile Safari/537.36");
                int code = connection.getResponseCode(); String location = header(connection, "Location");
                String body = read(code < 400 ? connection.getInputStream() : connection.getErrorStream());
                String tls = certificate(connection);
                if (code >= 300 && code < 400 && !location.isEmpty()) {
                    current = new URL(url, location).toString(); validate(current); continue;
                }
                String verdict = classify(code, current, body);
                return target.name + " " + target.url + " → " + verdict + " · HTTP " + code + " · "
                        + (System.currentTimeMillis() - started) + " ms · 最终 " + clip(current, 180) + tls;
            } catch (Exception failure) {
                String message = safe(failure); String lower = message.toLowerCase(Locale.ROOT);
                String verdict = lower.contains("timed out") ? "timeout" : lower.contains("ssl") || lower.contains("certificate")
                        ? "tls_error" : "network_error";
                return target.name + " " + target.url + " → " + verdict + " · " + message + " · "
                        + (System.currentTimeMillis() - started) + " ms";
            } finally { if (connection != null) connection.disconnect(); }
        }
        return target.name + " " + target.url + " → redirect_loop（HTTPS 跳转超过 4 次）";
    }

    private void add(List<Target> out, Set<String> seen, String name, String value) throws Exception {
        URL url = validate(value); if (seen.add(url.toString())) out.add(new Target(name, url.toString()));
    }

    private URL validate(String value) throws Exception {
        URL url = new URL(value);
        if (!"https".equalsIgnoreCase(url.getProtocol()) || url.getUserInfo() != null || url.getHost().trim().isEmpty())
            throw new Exception("目标必须是无账号信息的 HTTPS 公网网址：" + clip(value, 160));
        InetAddress[] addresses = InetAddress.getAllByName(url.getHost());
        if (addresses.length == 0) throw new Exception("目标 DNS 无结果：" + url.getHost());
        for (InetAddress address : addresses) {
            String ip = IpParser.normalize(address.getHostAddress());
            if (ip == null || !IpParser.isPublic(ip)) throw new Exception("拒绝访问解析到私网/保留地址的目标：" + url.getHost());
        }
        return url;
    }

    private String classify(int code, String url, String body) {
        String text = (url + "\n" + clip(body, 32768)).toLowerCase(Locale.ROOT);
        for (String marker : new String[]{"unsupported country", "unsupported region", "not available in your country",
                "not available in your region", "地区不可用", "地区暂不支持"}) if (text.contains(marker)) return "geo_blocked（页面明确地区限制）";
        if (code == 429) return "rate_limited";
        if (code >= 500) return "upstream_error";
        if (code == 401 || text.contains("/login") || text.contains("sign in")) return "login_required（线路已到达）";
        if ((code == 403 || code == 503) && (text.contains("cloudflare") || text.contains("captcha") || text.contains("challenge")))
            return "challenge_or_waf（不能据此断言地区封锁）";
        if (code == 403) return "forbidden_ambiguous（可能地区/风控/WAF）";
        if (code >= 200 && code < 400) return "reachable";
        return "http_" + code;
    }

    private String certificate(HttpsURLConnection connection) {
        try {
            Certificate[] chain = connection.getServerCertificates(); if (chain.length == 0 || !(chain[0] instanceof X509Certificate)) return "";
            X509Certificate cert = (X509Certificate) chain[0]; byte[] digest = MessageDigest.getInstance("SHA-256").digest(cert.getEncoded());
            StringBuilder fp = new StringBuilder(); for (byte b : digest) fp.append(String.format(Locale.ROOT, "%02x", b & 255));
            SimpleDateFormat date = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.ROOT); date.setTimeZone(TimeZone.getTimeZone("UTC"));
            return " · TLS issuer=" + clip(cert.getIssuerX500Principal().getName(), 120) + " · 到期=" + date.format(cert.getNotAfter())
                    + " · SHA256=" + fp;
        } catch (Exception ignored) { return " · TLS证书元数据读取失败"; }
    }

    private String read(InputStream input) throws Exception {
        if (input == null) return ""; try (InputStream in = input; ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[4096]; int read;
            while ((read = in.read(buffer)) >= 0 && out.size() < 128 * 1024) out.write(buffer, 0, Math.min(read, 128 * 1024 - out.size()));
            return new String(out.toByteArray(), java.nio.charset.StandardCharsets.UTF_8);
        }
    }

    private String header(HttpURLConnection c, String name) { String value = c.getHeaderField(name); return value == null ? "" : value.trim(); }
    private String clip(String value, int max) { if (value == null) return ""; return value.length() <= max ? value : value.substring(0, max); }
    private String safe(Exception error) { String value = error.getMessage(); return value == null || value.trim().isEmpty() ? error.getClass().getSimpleName() : clip(value.replace('\n', ' '), 240); }
}
