package com.fool.ipbatch;

import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.Uri;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.Proxy;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/** Selects subscription nodes through an already-running loopback Mihomo/Clash controller and probes real routes. */
public final class RealSubscriptionTester {
    private static final int MAX_CONTROLLER_BODY = 4 * 1024 * 1024;
    private static final int MAX_TARGET_BODY = 128 * 1024;
    private static final String[][] AI_TARGETS = new String[][]{
            {"ChatGPT", "https://chatgpt.com/"}, {"Claude", "https://claude.ai/new"},
            {"Gemini", "https://gemini.google.com/app"}, {"AI Studio", "https://aistudio.google.com/app/prompts/new_chat"},
            {"Grok", "https://grok.com/"}, {"Perplexity", "https://www.perplexity.ai/"},
            {"Copilot", "https://copilot.microsoft.com/"}, {"DeepSeek", "https://chat.deepseek.com/"},
            {"Qwen", "https://chat.qwen.ai/"}
    };

    public String run(Context context, String subscriptionUrl, String controllerUrl, String secret,
                      String requestedNode, String customTargets, boolean openBrowser) throws Exception {
        if (!hasActiveSystemVpn(context)) throw new Exception("未检测到 Android 系统 VPN；请先在 Clash/Mihomo/Clash Mate 开启 TUN/VPN");
        String controller = validateController(controllerUrl);
        Controller api = new Controller(controller, secret == null ? "" : secret.trim(), 8000);
        JSONObject version = api.json("/version", "GET", null);
        JSONObject configs = api.json("/configs", "GET", null);
        JSONObject tun = configs.optJSONObject("tun");
        if (!(tun != null ? tun.optBoolean("enable", false) : configs.optBoolean("tun", false))) {
            throw new Exception("本地控制器可访问，但 /configs 显示 TUN 未启用");
        }

        SubscriptionDownloader.Download download = new SubscriptionDownloader().download(
                subscriptionUrl, "Clash.Meta", 15000, false);
        SubscriptionParser.Report parsed = SubscriptionParser.parse(download.content);
        Set<String> subscriptionNames = new LinkedHashSet<>();
        for (SubscriptionParser.NodeEndpoint node : parsed.nodes) if (!node.name.trim().isEmpty()) subscriptionNames.add(node.name.trim());
        if (subscriptionNames.isEmpty()) throw new Exception("订阅没有可与控制器匹配的节点名称");

        JSONObject proxyRoot = api.json("/proxies", "GET", null);
        JSONObject proxies = proxyRoot.optJSONObject("proxies");
        if (proxies == null) throw new Exception("控制器未返回 proxies 对象");
        Group group = chooseGroup(proxies, subscriptionNames);
        List<String> selected = new ArrayList<>();
        String exact = requestedNode == null ? "" : requestedNode.trim();
        if (!exact.isEmpty()) {
            if (!group.overlap.contains(exact)) throw new Exception("指定节点不同时存在于订阅和控制器策略组：" + exact);
            selected.add(exact);
        } else {
            for (String node : group.overlap) { if (selected.size() >= 20) break; selected.add(node); }
        }
        if (selected.isEmpty()) throw new Exception("控制器策略组与订阅节点名称没有交集");
        if (openBrowser && selected.size() != 1) throw new Exception("打开真实对话页面时必须填写一个精确节点名称");
        List<Target> targets = targets(customTargets);

        StringBuilder report = new StringBuilder();
        report.append("订阅真实测试（Android 系统 VPN）")
                .append("\n控制器：").append(controller).append("；版本：").append(version.optString("version", version.toString()))
                .append("\nTUN：已启用；策略组：").append(group.name).append("；原节点：").append(group.original)
                .append("\n订阅解析节点：").append(parsed.nodes.size()).append("；匹配：").append(group.overlap.size())
                .append("；本次测试：").append(selected.size())
                .append("\n基线出口：").append(new ExitIpDetector().detect(8000).summary())
                .append("\n说明：下载订阅只用于解析和名称匹配；程序不会连接订阅中的服务器端口。真正流量由已运行的系统 VPN 承载。\n");
        String lastSelected = "";
        boolean restored = false;
        Exception restoreFailure = null;
        try {
            for (String node : selected) {
                api.json("/proxies/" + Uri.encode(group.name), "PUT", new JSONObject().put("name", node));
                lastSelected = node;
                Thread.sleep(1400);
                JSONObject currentRoot = api.json("/proxies", "GET", null);
                JSONObject currentGroup = currentRoot.optJSONObject("proxies").optJSONObject(group.name);
                String actual = currentGroup == null ? "" : currentGroup.optString("now", "");
                report.append("\n\n【节点】").append(node).append("\n控制器确认：")
                        .append(node.equals(actual) ? "成功" : "失败（实际 " + actual + "）");
                if (!node.equals(actual)) continue;
                ExitIpDetector.Report exit = new ExitIpDetector().detect(8000);
                report.append("\n出口：").append(exit.ips.isEmpty() ? exit.summary() : IpResult.join(exit.ips, ", ") + "；" + exit.agreement);
                for (Target target : targets) report.append("\n").append(probe(target, 12000));
            }
        } finally {
            if (!openBrowser && !group.original.isEmpty()) {
                try { api.json("/proxies/" + Uri.encode(group.name), "PUT", new JSONObject().put("name", group.original)); restored = true; }
                catch (Exception failure) { restoreFailure = failure; }
            }
        }
        report.append("\n\n【恢复】").append(openBrowser
                ? "浏览器模式按设计保留测试节点：" + lastSelected + "；完成后请在代理客户端恢复。"
                : restored ? "已恢复原节点：" + group.original : "恢复失败：" + safe(restoreFailure));
        report.append("\n\n【判定边界】\n")
                .append("- 请求的是 AI 对话网址而非产品登录入口；不发送 Cookie、账号、API Key 或消息。\n")
                .append("- 跳转到登录页表示线路能到达平台，但当前无登录会话；不判为地区封锁。\n")
                .append("- 403 可能是地区、WAF、机器人挑战或风控；只有正文明确出现国家/地区限制时才标记 geo_blocked。\n")
                .append("- 分应用代理、规则分流和 fake-IP 可让不同域名走不同路线，请结合每节点出口与浏览器实测。\n")
                .append("- 控制器密钥和订阅原文均未写入报告或持久化。");
        if (openBrowser) {
            for (Target target : targets) {
                Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse(target.url));
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK); context.startActivity(intent);
            }
        }
        return report.toString();
    }

    private boolean hasActiveSystemVpn(Context context) {
        ConnectivityManager manager = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (manager == null) return false;
        Network active = manager.getActiveNetwork();
        NetworkCapabilities caps = active == null ? null : manager.getNetworkCapabilities(active);
        if (caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return true;
        for (Network network : manager.getAllNetworks()) {
            NetworkCapabilities value = manager.getNetworkCapabilities(network);
            if (value != null && value.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                    && value.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) return true;
        }
        return false;
    }

    private Group chooseGroup(JSONObject proxies, Set<String> names) throws Exception {
        Group best = null;
        java.util.Iterator<String> keys = proxies.keys();
        while (keys.hasNext()) {
            String name = keys.next(); JSONObject item = proxies.optJSONObject(name); if (item == null) continue;
            JSONArray all = item.optJSONArray("all"); if (all == null) continue;
            List<String> overlap = new ArrayList<>();
            for (int i = 0; i < all.length(); i++) { String node = all.optString(i, ""); if (names.contains(node)) overlap.add(node); }
            if (!overlap.isEmpty() && (best == null || overlap.size() > best.overlap.size())) best = new Group(name, item.optString("now", ""), overlap);
        }
        if (best == null) throw new Exception("找不到包含该订阅节点名称的可选策略组");
        return best;
    }

    private List<Target> targets(String custom) throws Exception {
        List<Target> values = new ArrayList<>(); Set<String> seen = new LinkedHashSet<>();
        for (String[] row : AI_TARGETS) addTarget(values, seen, row[0], row[1]);
        if (custom != null) for (String raw : custom.split("[,\n]")) {
            String value = raw.trim(); if (value.isEmpty()) continue;
            if (!value.contains("://")) value = "https://" + value;
            addTarget(values, seen, "自定义", value);
            if (values.size() > 24) throw new Exception("网址最多 24 个");
        }
        return values;
    }

    private void addTarget(List<Target> targets, Set<String> seen, String name, String value) throws Exception {
        URL url = new URL(value);
        if (!"https".equalsIgnoreCase(url.getProtocol()) || url.getUserInfo() != null || url.getHost().isEmpty()) throw new Exception("目标必须是无账号信息的 HTTPS 公网网址：" + value);
        InetAddress[] addresses = InetAddress.getAllByName(url.getHost());
        if (addresses.length == 0) throw new Exception("目标 DNS 无结果：" + url.getHost());
        for (InetAddress address : addresses) {
            String ip = IpParser.normalize(address.getHostAddress());
            if (ip == null || !IpParser.isPublic(ip)) throw new Exception("拒绝访问解析到私网/保留地址的目标：" + url.getHost());
        }
        if (seen.add(url.toString())) targets.add(new Target(name, url.toString()));
    }

    private String probe(Target target, int timeout) {
        long started = System.currentTimeMillis(); HttpURLConnection connection = null;
        try {
            connection = (HttpURLConnection) new URL(target.url).openConnection();
            connection.setConnectTimeout(timeout); connection.setReadTimeout(timeout); connection.setInstanceFollowRedirects(false); connection.setUseCaches(false);
            connection.setRequestMethod("GET"); connection.setRequestProperty("Accept", "text/html,application/xhtml+xml,*/*;q=0.6");
            connection.setRequestProperty("User-Agent", "Mozilla/5.0 (Android; IPBatchInspector real-route probe)");
            int code = connection.getResponseCode(); String location = header(connection, "Location");
            String body = readLimited(code >= 200 && code < 400 ? connection.getInputStream() : connection.getErrorStream(), MAX_TARGET_BODY);
            String verdict = classify(code, location, body);
            return target.name + " " + target.url + " → " + verdict + " · HTTP " + code + " · " + (System.currentTimeMillis() - started) + " ms"
                    + (location.isEmpty() ? "" : " · Location " + clip(location, 180));
        } catch (Exception failure) {
            String message = safe(failure); String lower = message.toLowerCase(Locale.ROOT);
            String verdict = lower.contains("timed out") ? "timeout" : lower.contains("ssl") || lower.contains("certificate") ? "tls_error" : "network_error";
            return target.name + " " + target.url + " → " + verdict + " · " + message + " · " + (System.currentTimeMillis() - started) + " ms";
        } finally { if (connection != null) connection.disconnect(); }
    }

    private String classify(int code, String location, String body) {
        String text = (location + "\n" + clip(body, 32768)).toLowerCase(Locale.ROOT);
        for (String marker : new String[]{"unsupported country", "unsupported region", "not available in your country", "not available in your region", "地区不可用", "地区暂不支持"})
            if (text.contains(marker)) return "geo_blocked（明确地区限制）";
        if (code == 429) return "rate_limited";
        if (code >= 500) return "upstream_error";
        if (code == 401 || code == 407) return "authentication_required（已到达）";
        if ((code == 403 || code == 503) && (text.contains("cloudflare") || text.contains("captcha") || text.contains("challenge"))) return "challenge";
        if (code >= 300 && code < 400) return location.toLowerCase(Locale.ROOT).matches(".*(login|signin|auth|account).*") ? "authentication_required（登录跳转，已到达）" : "redirect（已到达）";
        if (code >= 200 && code < 400) return (text.contains("sign in") || text.contains("log in") || text.contains("登录")) ? "reachable_auth_ui" : "reachable";
        return "blocked_or_rejected";
    }

    private String validateController(String value) throws Exception {
        URL url = new URL(value == null || value.trim().isEmpty() ? "http://127.0.0.1:9090" : value.trim());
        String host = url.getHost().toLowerCase(Locale.ROOT);
        if (!"http".equalsIgnoreCase(url.getProtocol()) || !(host.equals("127.0.0.1") || host.equals("localhost") || host.equals("::1"))
                || url.getPort() < 1 || url.getUserInfo() != null || (!url.getPath().isEmpty() && !url.getPath().equals("/")) || url.getQuery() != null)
            throw new Exception("控制器仅允许 http://127.0.0.1:端口、localhost 或 [::1]");
        String authority = host.contains(":") ? "[" + host + "]:" + url.getPort() : host + ":" + url.getPort();
        return "http://" + authority;
    }

    private String readLimited(InputStream input, int max) throws Exception {
        if (input == null) return ""; try { ByteArrayOutputStream out = new ByteArrayOutputStream(); byte[] buffer = new byte[8192]; int read;
            while ((read = input.read(buffer)) >= 0) { if (read == 0) continue; int allowed = Math.min(read, max - out.size()); if (allowed > 0) out.write(buffer, 0, allowed); if (out.size() >= max) break; }
            return new String(out.toByteArray(), StandardCharsets.UTF_8); } finally { input.close(); }
    }
    private static String header(HttpURLConnection connection, String name) { String value = connection.getHeaderField(name); return value == null ? "" : value.replace('\n', ' ').replace('\r', ' '); }
    private static String clip(String value, int max) { return value == null ? "" : value.length() <= max ? value : value.substring(0, max); }
    private static String safe(Exception error) { if (error == null) return "未知错误"; String value = error.getMessage(); return clip(value == null ? error.getClass().getSimpleName() : value.replace('\n', ' '), 300); }

    private static final class Group { final String name, original; final List<String> overlap; Group(String name, String original, List<String> overlap) { this.name = name; this.original = original; this.overlap = overlap; } }
    private static final class Target { final String name, url; Target(String name, String url) { this.name = name; this.url = url; } }

    private final class Controller {
        final String base, secret; final int timeout;
        Controller(String base, String secret, int timeout) { this.base = base; this.secret = secret; this.timeout = timeout; }
        JSONObject json(String path, String method, JSONObject payload) throws Exception {
            HttpURLConnection connection = (HttpURLConnection) new URL(base + path).openConnection(Proxy.NO_PROXY);
            try {
                connection.setConnectTimeout(timeout); connection.setReadTimeout(timeout); connection.setRequestMethod(method); connection.setUseCaches(false);
                connection.setRequestProperty("Accept", "application/json");
                if (!secret.isEmpty()) connection.setRequestProperty("Authorization", "Bearer " + secret);
                if (payload != null) { connection.setDoOutput(true); connection.setRequestProperty("Content-Type", "application/json"); byte[] bytes = payload.toString().getBytes(StandardCharsets.UTF_8); OutputStream output = connection.getOutputStream(); output.write(bytes); output.close(); }
                int code = connection.getResponseCode(); String body = readLimited(code >= 200 && code < 300 ? connection.getInputStream() : connection.getErrorStream(), MAX_CONTROLLER_BODY);
                if (code < 200 || code >= 300) throw new Exception("本地控制器 HTTP " + code + "：" + clip(body, 300));
                return body.trim().isEmpty() ? new JSONObject() : new JSONObject(body);
            } finally { connection.disconnect(); }
        }
    }
}
