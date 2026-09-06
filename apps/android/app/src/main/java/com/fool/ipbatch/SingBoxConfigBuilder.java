package com.fool.ipbatch;

import org.json.JSONArray;
import org.json.JSONObject;

import java.net.InetAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Converts common subscription records into isolated, temporary sing-box configurations. */
public final class SingBoxConfigBuilder {
    public static final int MAX_REAL_NODES = 20;

    public static final class Plan {
        public final String label;
        public final String protocol;
        public final String config;

        Plan(String label, String protocol, String config) {
            this.label = label;
            this.protocol = protocol;
            this.config = config;
        }
    }

    public static final class Result {
        public final List<Plan> plans = new ArrayList<>();
        public final List<String> warnings = new ArrayList<>();
        public int discovered;
        public int rejected;

        public String summary() {
            return "可真实测试 " + plans.size() + " / 发现 " + discovered + "；拒绝/不支持 " + rejected
                    + (warnings.isEmpty() ? "" : "；警告 " + warnings.size());
        }
    }

    public Result build(String content, String requestedNode) throws Exception {
        Result result = new Result();
        String text = decodeSubscription(content == null ? "" : content.trim());
        if (text.isEmpty()) throw new Exception("订阅内容为空");
        String exact = requestedNode == null ? "" : requestedNode.trim();
        if (text.startsWith("{") && new JSONObject(text).has("outbounds")) {
            parseNative(new JSONObject(text), exact, result);
        } else if (looksLikeClash(text)) {
            parseClash(text, exact, result);
        } else {
            parseLinks(text, exact, result);
        }
        if (!exact.isEmpty() && result.plans.isEmpty()) throw new Exception("订阅中没有可测试的精确节点：" + exact);
        if (result.plans.isEmpty()) throw new Exception("没有可转换为 sing-box 的受支持节点；查看警告可确认格式边界");
        return result;
    }

    private void parseLinks(String text, String exact, Result result) {
        for (String raw : text.split("[\\r\\n\\t ]+")) {
            if (!raw.contains("://")) continue;
            result.discovered++;
            try {
                JSONObject outbound = linkOutbound(raw.trim());
                String label = linkName(raw, outbound.optString("_label", "节点 " + result.discovered));
                if (!exact.isEmpty() && !exact.equals(label)) continue;
                outbound.put("tag", "selected");
                validateOutbound(outbound);
                addPlan(result, label, outbound.optString("type"), list(outbound));
            } catch (Exception failure) {
                result.rejected++;
                addWarning(result, "链接 " + result.discovered + "：" + safe(failure));
            }
            if (exact.isEmpty() && result.plans.size() >= MAX_REAL_NODES) break;
        }
    }

    private void parseNative(JSONObject root, String exact, Result result) throws Exception {
        JSONArray source = root.optJSONArray("outbounds");
        if (source == null) throw new Exception("sing-box JSON 没有 outbounds 数组");
        Map<String, JSONObject> byTag = new LinkedHashMap<>();
        for (int i = 0; i < source.length(); i++) {
            JSONObject item = source.optJSONObject(i);
            if (item == null) continue;
            String tag = item.optString("tag", "outbound-" + i);
            byTag.put(tag, item);
        }
        for (Map.Entry<String, JSONObject> entry : byTag.entrySet()) {
            JSONObject primary = entry.getValue();
            String type = primary.optString("type", "").toLowerCase(Locale.ROOT);
            if (!primary.has("server") || isMetaOutbound(type)) continue;
            result.discovered++;
            String label = entry.getKey();
            if (!exact.isEmpty() && !exact.equals(label)) continue;
            try {
                List<JSONObject> selected = new ArrayList<>();
                collectWithDetour(primary, byTag, selected, new LinkedHashSet<String>());
                for (JSONObject item : selected) validateOutbound(item);
                addPlan(result, label, type, selected);
            } catch (Exception failure) {
                result.rejected++;
                addWarning(result, label + "：" + safe(failure));
            }
            if (exact.isEmpty() && result.plans.size() >= MAX_REAL_NODES) break;
        }
    }

    private void collectWithDetour(JSONObject item, Map<String, JSONObject> byTag,
                                   List<JSONObject> output, Set<String> seen) throws Exception {
        String tag = item.optString("tag", "selected");
        if (!seen.add(tag)) throw new Exception("链式代理存在循环引用：" + tag);
        output.add(new JSONObject(item.toString()));
        String detour = item.optString("detour", "");
        if (!detour.isEmpty()) {
            JSONObject next = byTag.get(detour);
            if (next == null) throw new Exception("找不到链式出站：" + detour);
            collectWithDetour(next, byTag, output, seen);
        }
    }

    private void parseClash(String text, String exact, Result result) {
        List<Map<String, String>> records = clashRecords(text);
        Map<String, JSONObject> byName = new LinkedHashMap<>();
        Map<String, String> dialers = new LinkedHashMap<>();
        for (Map<String, String> record : records) {
            result.discovered++;
            try {
                String name = value(record, "name", "节点 " + result.discovered);
                JSONObject outbound = clashOutbound(record, "node-" + result.discovered);
                byName.put(name, outbound);
                String dialer = value(record, "dialer-proxy", "");
                if (!dialer.isEmpty()) dialers.put(name, dialer);
            } catch (Exception failure) {
                result.rejected++;
                addWarning(result, value(record, "name", "Clash 节点 " + result.discovered) + "：" + safe(failure));
            }
        }
        for (Map.Entry<String, JSONObject> entry : byName.entrySet()) {
            String name = entry.getKey();
            if (!exact.isEmpty() && !exact.equals(name)) continue;
            try {
                List<JSONObject> chain = new ArrayList<>();
                JSONObject primary = new JSONObject(entry.getValue().toString());
                primary.put("tag", "selected");
                chain.add(primary);
                String dialer = dialers.get(name);
                Set<String> seen = new LinkedHashSet<>();
                while (dialer != null && !dialer.isEmpty()) {
                    if (!seen.add(dialer)) throw new Exception("dialer-proxy 循环：" + dialer);
                    JSONObject nextSource = byName.get(dialer);
                    if (nextSource == null) throw new Exception("dialer-proxy 引用不存在：" + dialer);
                    String tag = "chain-" + chain.size();
                    chain.get(chain.size() - 1).put("detour", tag);
                    JSONObject next = new JSONObject(nextSource.toString());
                    next.put("tag", tag);
                    chain.add(next);
                    dialer = dialers.get(dialer);
                }
                for (JSONObject item : chain) validateOutbound(item);
                addPlan(result, name, primary.optString("type"), chain);
            } catch (Exception failure) {
                result.rejected++;
                addWarning(result, name + "：" + safe(failure));
            }
            if (exact.isEmpty() && result.plans.size() >= MAX_REAL_NODES) break;
        }
    }

    private JSONObject linkOutbound(String link) throws Exception {
        String scheme = link.substring(0, link.indexOf("://")).toLowerCase(Locale.ROOT);
        if ("vmess".equals(scheme)) return vmess(link.substring(link.indexOf("://") + 3));
        if ("ss".equals(scheme)) return shadowsocks(link);
        if ("ssr".equals(scheme)) throw new Exception("SSR 不受 sing-box 1.14 支持，只能普通解析，不能真实连接");
        URI uri = new URI(link);
        String host = uri.getHost();
        int port = uri.getPort();
        if (host == null || port < 1) throw new Exception("缺少服务器或端口");
        Map<String, String> query = query(uri.getRawQuery());
        String user = decode(uri.getRawUserInfo());
        JSONObject out = new JSONObject().put("tag", "selected").put("server", host).put("server_port", port);
        if ("vless".equals(scheme)) {
            out.put("type", "vless").put("uuid", user);
            put(out, "flow", query.get("flow"));
        } else if ("trojan".equals(scheme)) {
            out.put("type", "trojan").put("password", user);
        } else if ("hysteria2".equals(scheme) || "hy2".equals(scheme)) {
            out.put("type", "hysteria2").put("password", user);
            put(out, "up_mbps", number(query.get("upmbps"))); put(out, "down_mbps", number(query.get("downmbps")));
            if (query.containsKey("obfs")) out.put("obfs", new JSONObject().put("type", query.get("obfs"))
                    .put("password", value(query, "obfs-password", "")));
        } else if ("hysteria".equals(scheme)) {
            out.put("type", "hysteria"); put(out, "auth_str", user); put(out, "up_mbps", number(query.get("upmbps")));
            put(out, "down_mbps", number(query.get("downmbps"))); put(out, "obfs", query.get("obfs"));
        } else if ("tuic".equals(scheme)) {
            String[] auth = user.split(":", 2);
            out.put("type", "tuic").put("uuid", auth[0]);
            if (auth.length > 1) out.put("password", auth[1]);
            put(out, "congestion_control", query.get("congestion_control"));
            put(out, "udp_relay_mode", query.get("udp_relay_mode"));
        } else if ("socks".equals(scheme) || "socks5".equals(scheme)) {
            out.put("type", "socks"); auth(out, user);
        } else if ("http".equals(scheme) || "https".equals(scheme)) {
            out.put("type", "http"); auth(out, user);
        } else {
            throw new Exception("未支持的真实连接协议：" + scheme);
        }
        addTlsAndTransport(out, query, scheme);
        return out;
    }

    private JSONObject vmess(String encoded) throws Exception {
        String value = encoded;
        int hash = value.indexOf('#'); if (hash >= 0) value = value.substring(0, hash);
        JSONObject source = new JSONObject(new String(Base64Compat.decode(value), StandardCharsets.UTF_8));
        JSONObject out = new JSONObject().put("type", "vmess").put("tag", "selected")
                .put("server", source.getString("add")).put("server_port", Integer.parseInt(source.optString("port", "0")))
                .put("uuid", source.getString("id"));
        put(out, "security", source.optString("scy", "auto"));
        int aid = Integer.parseInt(source.optString("aid", "0")); if (aid > 0) out.put("alter_id", aid);
        Map<String, String> params = new LinkedHashMap<>();
        params.put("type", source.optString("net", "tcp")); params.put("host", source.optString("host", ""));
        params.put("path", source.optString("path", "")); params.put("security", source.optString("tls", ""));
        params.put("sni", source.optString("sni", "")); params.put("fp", source.optString("fp", ""));
        addTlsAndTransport(out, params, "vmess");
        out.put("_label", source.optString("ps", "VMess"));
        return out;
    }

    private JSONObject shadowsocks(String link) throws Exception {
        URI uri = new URI(link);
        String host = uri.getHost(); int port = uri.getPort(); String user = decode(uri.getRawUserInfo());
        if (host == null) {
            String body = link.substring(5); int hash = body.indexOf('#'); if (hash >= 0) body = body.substring(0, hash);
            int query = body.indexOf('?'); if (query >= 0) body = body.substring(0, query);
            String decoded = new String(Base64Compat.decode(body), StandardCharsets.UTF_8);
            URI normalized = new URI("ss://" + decoded); host = normalized.getHost(); port = normalized.getPort(); user = normalized.getRawUserInfo();
        } else if (user != null && !user.contains(":")) {
            user = new String(Base64Compat.decode(user), StandardCharsets.UTF_8);
        }
        Map<String, String> q = query(uri.getRawQuery());
        if (q.containsKey("plugin")) throw new Exception("Shadowsocks plugin 暂不在内嵌转换边界内");
        String[] auth = decode(user).split(":", 2);
        if (host == null || port < 1 || auth.length != 2) throw new Exception("SS 认证或地址无效");
        return new JSONObject().put("type", "shadowsocks").put("tag", "selected")
                .put("server", host).put("server_port", port).put("method", auth[0]).put("password", auth[1]);
    }

    private JSONObject clashOutbound(Map<String, String> item, String tag) throws Exception {
        String type = value(item, "type", "").toLowerCase(Locale.ROOT);
        String host = value(item, "server", ""); int port = integer(item.get("port"));
        if (host.isEmpty() || port < 1) throw new Exception("缺少 server/port");
        JSONObject out = new JSONObject().put("tag", tag).put("server", host).put("server_port", port);
        if ("ss".equals(type)) out.put("type", "shadowsocks").put("method", value(item, "cipher", ""))
                .put("password", value(item, "password", ""));
        else if ("vmess".equals(type)) out.put("type", "vmess").put("uuid", value(item, "uuid", ""))
                .put("security", value(item, "cipher", "auto")).put("alter_id", integer(value(item, "alterid", value(item, "alter-id", "0"))));
        else if ("vless".equals(type)) out.put("type", "vless").put("uuid", value(item, "uuid", ""));
        else if ("trojan".equals(type)) out.put("type", "trojan").put("password", value(item, "password", ""));
        else if ("hysteria2".equals(type) || "hy2".equals(type)) out.put("type", "hysteria2")
                .put("password", value(item, "password", value(item, "auth", "")));
        else if ("hysteria".equals(type)) out.put("type", "hysteria").put("auth_str", value(item, "auth-str", value(item, "auth", "")));
        else if ("tuic".equals(type)) out.put("type", "tuic").put("uuid", value(item, "uuid", ""))
                .put("password", value(item, "password", ""));
        else if ("socks5".equals(type) || "socks".equals(type)) { out.put("type", "socks"); auth(out, value(item, "username", "") + ":" + value(item, "password", "")); }
        else if ("http".equals(type)) { out.put("type", "http"); auth(out, value(item, "username", "") + ":" + value(item, "password", "")); }
        else throw new Exception("Clash 类型尚不能真实转换：" + type);
        if (truth(item.get("tls"))) item.put("security", "tls");
        addTlsAndTransport(out, item, type);
        return out;
    }

    private void addTlsAndTransport(JSONObject out, Map<String, String> p, String scheme) throws Exception {
        String security = value(p, "security", "");
        boolean tlsOn = "tls".equalsIgnoreCase(security) || "reality".equalsIgnoreCase(security)
                || "trojan".equals(scheme) || "hysteria".equals(scheme) || "hysteria2".equals(scheme)
                || "hy2".equals(scheme) || "tuic".equals(scheme) || truth(p.get("tls"));
        if (tlsOn) {
            JSONObject tls = new JSONObject().put("enabled", true);
            put(tls, "server_name", first(p.get("sni"), p.get("servername"), p.get("server-name")));
            if (truth(first(p.get("allowInsecure"), p.get("skip-cert-verify"), p.get("insecure")))) tls.put("insecure", true);
            String fingerprint = first(p.get("fp"), p.get("client-fingerprint"));
            if (!empty(fingerprint)) tls.put("utls", new JSONObject().put("enabled", true).put("fingerprint", fingerprint));
            if ("reality".equalsIgnoreCase(security) || p.containsKey("pbk") || p.containsKey("public-key")) {
                tls.put("reality", new JSONObject().put("enabled", true)
                        .put("public_key", first(p.get("pbk"), p.get("public-key")))
                        .put("short_id", first(p.get("sid"), p.get("short-id"))));
            }
            out.put("tls", tls);
        }
        String network = first(p.get("network"), p.get("type"));
        if ("ws".equalsIgnoreCase(network)) {
            JSONObject transport = new JSONObject().put("type", "ws"); put(transport, "path", p.get("path"));
            String host = first(p.get("host"), p.get("ws-host"));
            if (!empty(host)) transport.put("headers", new JSONObject().put("Host", host));
            out.put("transport", transport);
        } else if ("grpc".equalsIgnoreCase(network)) {
            out.put("transport", new JSONObject().put("type", "grpc")
                    .put("service_name", first(p.get("serviceName"), p.get("servicename"), p.get("grpc-service-name"))));
        }
    }

    private void addPlan(Result result, String label, String protocol, List<JSONObject> outboundItems) throws Exception {
        JSONObject config = new JSONObject();
        config.put("log", new JSONObject().put("level", "warn").put("timestamp", true));
        config.put("inbounds", new JSONArray().put(new JSONObject().put("type", "tun").put("tag", "tun-in")
                .put("address", new JSONArray().put("172.19.0.1/30").put("fdfe:dcba:9876::1/126"))
                .put("auto_route", true).put("strict_route", true).put("stack", "mixed")));
        JSONArray outbounds = new JSONArray();
        for (JSONObject item : outboundItems) {
            JSONObject clean = new JSONObject(item.toString()); clean.remove("_label"); outbounds.put(clean);
        }
        outbounds.put(new JSONObject().put("type", "direct").put("tag", "direct"));
        config.put("outbounds", outbounds);
        config.put("dns", new JSONObject().put("servers", new JSONArray()
                .put(new JSONObject().put("type", "udp").put("tag", "local").put("server", "223.5.5.5").put("detour", "direct"))
                .put(new JSONObject().put("type", "https").put("tag", "remote").put("server", "1.1.1.1").put("detour", "selected")))
                .put("final", "remote").put("strategy", "prefer_ipv4"));
        config.put("route", new JSONObject().put("auto_detect_interface", true).put("default_domain_resolver", "local").put("final", "selected")
                .put("rules", new JSONArray().put(new JSONObject().put("action", "sniff"))
                        .put(new JSONObject().put("protocol", "dns").put("action", "hijack-dns"))
                        .put(new JSONObject().put("ip_is_private", true).put("action", "reject"))));
        result.plans.add(new Plan(label, protocol, config.toString()));
    }

    private void validateOutbound(JSONObject out) throws Exception {
        String server = out.optString("server", "").trim();
        if (server.isEmpty()) return;
        String normalized = IpParser.normalize(server);
        if (normalized != null) {
            if (!IpParser.isPublic(normalized)) throw new Exception("拒绝私网/保留节点服务器：" + server);
            return;
        }
        InetAddress[] answers = InetAddress.getAllByName(server);
        if (answers.length == 0) throw new Exception("节点域名 DNS 无结果：" + server);
        for (InetAddress answer : answers) {
            String ip = IpParser.normalize(answer.getHostAddress());
            if (ip == null || !IpParser.isPublic(ip)) throw new Exception("节点域名解析到私网/保留地址：" + server);
        }
    }

    private List<Map<String, String>> clashRecords(String text) {
        List<Map<String, String>> output = new ArrayList<>(); Map<String, String> current = null;
        boolean proxies = false; int sectionIndent = -1;
        for (String raw : text.replace("\r", "").split("\n")) {
            String trimmed = stripComment(raw).trim(); if (trimmed.isEmpty()) continue;
            int indent = raw.length() - raw.replaceFirst("^\\s+", "").length();
            if (trimmed.matches("(?i)^proxies\\s*:\\s*$")) { proxies = true; sectionIndent = indent; continue; }
            if (proxies && indent <= sectionIndent && !trimmed.startsWith("-")) break;
            if (!proxies) continue;
            if (trimmed.startsWith("-")) {
                if (current != null) output.add(current); current = new LinkedHashMap<>();
                String rest = trimmed.substring(1).trim();
                if (rest.startsWith("{") && rest.endsWith("}")) parseInline(rest.substring(1, rest.length() - 1), current);
                else parseField(rest, current);
            } else if (current != null) parseField(trimmed, current);
        }
        if (current != null) output.add(current);
        return output;
    }

    private void parseInline(String text, Map<String, String> out) {
        for (String part : text.split(",(?=(?:[^'\"]|'[^']*'|\"[^\"]*\")*$)")) parseField(part.trim(), out);
    }

    private void parseField(String text, Map<String, String> out) {
        int colon = text.indexOf(':'); if (colon <= 0) return;
        String key = text.substring(0, colon).trim().toLowerCase(Locale.ROOT); String value = unquote(text.substring(colon + 1).trim());
        if (!value.isEmpty() && !value.startsWith("{") && !value.startsWith("[")) out.put(key, value);
    }

    private Map<String, String> query(String raw) {
        Map<String, String> out = new LinkedHashMap<>(); if (raw == null) return out;
        for (String pair : raw.split("&")) { int at = pair.indexOf('='); out.put(decode(at < 0 ? pair : pair.substring(0, at)), decode(at < 0 ? "" : pair.substring(at + 1))); }
        return out;
    }

    private String decodeSubscription(String text) {
        if (text.contains("://") || text.startsWith("{") || looksLikeClash(text)) return text;
        try {
            String decoded = new String(Base64Compat.decode(text.replaceAll("\\s", "")), StandardCharsets.UTF_8);
            return decoded.contains("://") || looksLikeClash(decoded) || decoded.trim().startsWith("{") ? decoded : text;
        } catch (Exception ignored) { return text; }
    }

    private String linkName(String link, String fallback) {
        try {
            int hash = link.indexOf('#');
            if (hash >= 0 && hash + 1 < link.length()) return decode(link.substring(hash + 1));
        } catch (Exception ignored) { }
        return fallback;
    }

    private boolean looksLikeClash(String text) { return text.matches("(?s).*\\bproxies\\s*:.*"); }
    private boolean isMetaOutbound(String type) { return "direct".equals(type) || "block".equals(type) || "dns".equals(type)
            || "selector".equals(type) || "urltest".equals(type); }
    private List<JSONObject> list(JSONObject value) { List<JSONObject> out = new ArrayList<>(); out.add(value); return out; }
    private void auth(JSONObject out, String user) throws Exception { if (user == null) return; String[] parts = user.split(":", 2); if (!parts[0].isEmpty()) out.put("username", parts[0]); if (parts.length > 1) out.put("password", parts[1]); }
    private void put(JSONObject out, String key, Object value) throws Exception { if (value != null && !String.valueOf(value).trim().isEmpty() && !"0".equals(String.valueOf(value))) out.put(key, value); }
    private Integer number(String value) { try { return empty(value) ? null : Integer.valueOf(value.replaceAll("[^0-9]", "")); } catch (Exception ignored) { return null; } }
    private int integer(String value) { try { return Integer.parseInt(unquote(value)); } catch (Exception ignored) { return 0; } }
    private boolean truth(String value) { return value != null && ("true".equalsIgnoreCase(value) || "1".equals(value)); }
    private String first(String... values) { for (String value : values) if (!empty(value)) return value; return ""; }
    private String value(Map<String, String> values, String key, String fallback) { String value = values.get(key); return empty(value) ? fallback : value; }
    private boolean empty(String value) { return value == null || value.trim().isEmpty(); }
    private String decode(String value) { try { return value == null ? "" : URLDecoder.decode(value, StandardCharsets.UTF_8.name()); } catch (Exception ignored) { return value == null ? "" : value; } }
    private String unquote(String value) { if (value == null) return ""; value = value.trim(); if (value.length() > 1 && ((value.startsWith("\"") && value.endsWith("\"")) || (value.startsWith("'") && value.endsWith("'")))) return value.substring(1, value.length() - 1); return value; }
    private String stripComment(String line) { boolean single = false, doub = false; for (int i = 0; i < line.length(); i++) { char c = line.charAt(i); if (c == '\'' && !doub) single = !single; else if (c == '"' && !single) doub = !doub; else if (c == '#' && !single && !doub) return line.substring(0, i); } return line; }
    private String safe(Exception e) { String value = e.getMessage(); return empty(value) ? e.getClass().getSimpleName() : value.replace('\n', ' '); }
    private void addWarning(Result result, String value) { if (result.warnings.size() < 80) result.warnings.add(value); }
}
