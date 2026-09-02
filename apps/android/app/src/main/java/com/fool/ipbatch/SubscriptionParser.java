package com.fool.ipbatch;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Parses subscription text only. It never opens a socket or connects to a proxy node. */
public final class SubscriptionParser {
    public static final int MAX_NODES = 1500;

    public static final class NodeEndpoint {
        public final String protocol;
        public final String name;
        public final String host;
        public final int port;

        NodeEndpoint(String protocol, String name, String host, int port) {
            this.protocol = protocol;
            this.name = name;
            this.host = host;
            this.port = port;
        }

        public String label() {
            StringBuilder out = new StringBuilder(protocol.toUpperCase(Locale.ROOT));
            if (!name.isEmpty()) out.append(" ").append(name);
            out.append(" @ ").append(host);
            if (port > 0) out.append(":").append(port);
            return out.toString();
        }
    }

    public static final class Report {
        public final List<NodeEndpoint> nodes = new ArrayList<>();
        public final List<String> warnings = new ArrayList<>();
        public final List<String> providerUrls = new ArrayList<>();
        public final Map<String, Integer> protocols = new LinkedHashMap<>();
        public int uriNodes;
        public int yamlNodes;
        public int decodedLayers;
        public int rejected;
        public int duplicates;
        public int unsupported;
        public int chainReferences;
        public boolean truncated;

        public String summary() {
            StringBuilder types = new StringBuilder();
            for (Map.Entry<String, Integer> entry : protocols.entrySet()) {
                if (types.length() > 0) types.append("、");
                types.append(entry.getKey().toUpperCase(Locale.ROOT)).append(" ").append(entry.getValue());
            }
            return "节点 " + nodes.size() + "；协议 " + (types.length() == 0 ? "未识别" : types)
                    + "；URI " + uriNodes + "；YAML " + yamlNodes
                    + (decodedLayers > 0 ? "；Base64 解码 " + decodedLayers + " 层" : "")
                    + (chainReferences > 0 ? "；链式引用 " + chainReferences : "")
                    + (providerUrls.isEmpty() ? "" : "；远程 Provider " + providerUrls.size())
                    + (duplicates > 0 ? "；重复 " + duplicates : "")
                    + (rejected > 0 ? "；无效 " + rejected : "")
                    + (unsupported > 0 ? "；未支持 " + unsupported : "")
                    + (truncated ? "；已达到节点上限" : "");
        }
    }

    private static final Pattern SCHEME = Pattern.compile("(?i)(ssr?|vmess|vless|trojan|hysteria2?|hy2|tuic|socks5?|https?)://[^\\s<>'\\\"]+");
    private static final Pattern JSON_STRING = Pattern.compile("\"%s\"\\s*:\\s*\"((?:\\\\.|[^\"])*)\"");
    private static final Pattern JSON_NUMBER = Pattern.compile("\"%s\"\\s*:\\s*\"?(\\d{1,5})\"?");
    private static final Pattern INLINE_KEY = Pattern.compile("(?i)(?:^|[,\\s{])%s\\s*:\\s*(?:\"([^\"]*)\"|'([^']*)'|([^,}\\s]+))");

    private SubscriptionParser() {}

    public static Report parse(String content) {
        Report report = new Report();
        if (content == null || content.trim().isEmpty()) {
            report.warnings.add("订阅内容为空");
            return report;
        }
        Set<String> seen = new LinkedHashSet<>();
        parseLayer(stripBom(content), report, seen, 0);
        if (report.nodes.isEmpty()) report.warnings.add("没有找到可提取服务器地址的节点；可能是私有或加密格式");
        return report;
    }

    public static void merge(Report target, Report extra) {
        Set<String> seen = new LinkedHashSet<>();
        for (NodeEndpoint node : target.nodes) seen.add(node.protocol + "|" + node.host.toLowerCase(Locale.ROOT) + "|" + node.port);
        target.uriNodes += extra.uriNodes;
        target.yamlNodes += extra.yamlNodes;
        target.decodedLayers += extra.decodedLayers;
        target.rejected += extra.rejected;
        target.duplicates += extra.duplicates;
        target.unsupported += extra.unsupported;
        target.chainReferences += extra.chainReferences;
        target.truncated |= extra.truncated;
        for (NodeEndpoint node : extra.nodes) add(target, seen, node);
        for (String url : extra.providerUrls) if (!target.providerUrls.contains(url) && target.providerUrls.size() < 20) target.providerUrls.add(url);
        target.warnings.addAll(extra.warnings);
    }

    private static void parseLayer(String content, Report report, Set<String> seen, int depth) {
        if (depth > 2 || report.truncated) return;
        String trimmed = content.trim();
        if (looksLikeBase64(trimmed)) {
            String decoded = decodeBase64Text(trimmed);
            if (decoded != null && looksLikeSubscription(decoded)) {
                report.decodedLayers++;
                parseLayer(decoded, report, seen, depth + 1);
                return;
            }
        }
        parseYaml(content, report, seen);
        Matcher matcher = SCHEME.matcher(content);
        while (matcher.find() && !report.truncated) {
            String token = trimLink(matcher.group());
            NodeEndpoint node = parseUri(token, report);
            if (node != null) {
                report.uriNodes++;
                add(report, seen, node);
            }
        }
    }

    private static void parseYaml(String content, Report report, Set<String> seen) {
        String[] lines = content.replace("\r", "").split("\n");
        boolean inProxies = false;
        boolean inProviders = false;
        int sectionIndent = -1;
        int providerIndent = -1;
        MutableNode current = null;
        for (String raw : lines) {
            String noComment = stripYamlComment(raw);
            String trimmed = noComment.trim();
            if (trimmed.isEmpty()) continue;
            int indent = indentation(noComment);
            if (trimmed.matches("(?i)^proxies\\s*:\\s*$")) {
                flush(current, report, seen);
                current = null;
                inProxies = true;
                sectionIndent = indent;
                continue;
            }
            if (trimmed.matches("(?i)^proxy-providers\\s*:\\s*$")) {
                inProviders = true;
                providerIndent = indent;
                continue;
            }
            if (inProxies && indent <= sectionIndent && !trimmed.startsWith("-")) {
                flush(current, report, seen);
                current = null;
                inProxies = false;
            }
            if (inProviders && indent <= providerIndent && !trimmed.matches("(?i)^proxy-providers\\s*:\\s*$")) inProviders = false;
            if (inProviders) {
                String providerUrl = "";
                if (trimmed.startsWith("url:")) providerUrl = unquote(trimmed.substring(4).trim());
                else if (trimmed.contains("url:")) providerUrl = inlineValue(trimmed, "url");
                if (providerUrl.startsWith("https://") && !report.providerUrls.contains(providerUrl) && report.providerUrls.size() < 20) {
                    report.providerUrls.add(providerUrl);
                }
            }
            if (!inProxies) continue;
            if (trimmed.startsWith("- {")) {
                flush(current, report, seen);
                current = null;
                String type = inlineValue(trimmed, "type");
                String host = inlineValue(trimmed, "server");
                String name = inlineValue(trimmed, "name");
                int port = parsePort(inlineValue(trimmed, "port"));
                if (!type.isEmpty() && !host.isEmpty()) {
                    add(report, seen, new NodeEndpoint(normalizeProtocol(type), cleanName(name), cleanHost(host), port));
                    report.yamlNodes++;
                } else report.rejected++;
                if (!inlineValue(trimmed, "dialer-proxy").isEmpty()) report.chainReferences++;
                continue;
            }
            if (trimmed.startsWith("- ")) {
                flush(current, report, seen);
                current = new MutableNode();
                parseYamlField(trimmed.substring(2).trim(), current, report);
            } else if (current != null) {
                parseYamlField(trimmed, current, report);
            }
        }
        flush(current, report, seen);
    }

    private static void parseYamlField(String line, MutableNode node, Report report) {
        int colon = line.indexOf(':');
        if (colon <= 0) return;
        String key = line.substring(0, colon).trim().toLowerCase(Locale.ROOT);
        String value = unquote(line.substring(colon + 1).trim());
        if ("name".equals(key)) node.name = cleanName(value);
        else if ("type".equals(key)) node.protocol = normalizeProtocol(value);
        else if ("server".equals(key)) node.host = cleanHost(value);
        else if ("port".equals(key)) node.port = parsePort(value);
        else if ("dialer-proxy".equals(key) && !value.isEmpty()) report.chainReferences++;
    }

    private static void flush(MutableNode node, Report report, Set<String> seen) {
        if (node == null) return;
        if (!node.protocol.isEmpty() && !node.host.isEmpty()) {
            add(report, seen, new NodeEndpoint(node.protocol, node.name, node.host, node.port));
            report.yamlNodes++;
        } else if (!node.host.isEmpty() || !node.protocol.isEmpty()) {
            report.rejected++;
        }
    }

    private static NodeEndpoint parseUri(String token, Report report) {
        int schemeEnd = token.indexOf("://");
        if (schemeEnd <= 0) return null;
        String scheme = token.substring(0, schemeEnd).toLowerCase(Locale.ROOT);
        String body = token.substring(schemeEnd + 3);
        try {
            if ("vmess".equals(scheme)) return parseVmess(body);
            if ("ssr".equals(scheme)) return parseSsr(body);
            if ("ss".equals(scheme)) return parseSs(body);
            if ("http".equals(scheme) || "https".equals(scheme)) {
                if (!looksLikeProxyUri(body)) return null;
            }
            if (!isSupportedScheme(scheme)) {
                report.unsupported++;
                return null;
            }
            return parseAuthority(scheme, body);
        } catch (Exception ignored) {
            report.rejected++;
            return null;
        }
    }

    private static NodeEndpoint parseVmess(String body) {
        String decoded = decodeBase64Text(cut(body, '#', '?'));
        if (decoded == null) return null;
        String host = jsonString(decoded, "add");
        int port = jsonNumber(decoded, "port");
        String name = jsonString(decoded, "ps");
        if (host.isEmpty()) return null;
        return new NodeEndpoint("vmess", cleanName(name), cleanHost(host), port);
    }

    private static NodeEndpoint parseSsr(String body) {
        String decoded = decodeBase64Text(cut(body, '#'));
        if (decoded == null) return null;
        int slash = decoded.indexOf('/');
        String head = slash >= 0 ? decoded.substring(0, slash) : decoded;
        String[] parts = head.split(":", 6);
        if (parts.length < 6) return null;
        String name = queryValue(decoded, "remarks");
        if (!name.isEmpty()) {
            String decodedName = decodeBase64Text(name);
            if (decodedName != null) name = decodedName;
        }
        return new NodeEndpoint("ssr", cleanName(name), cleanHost(parts[0]), parsePort(parts[1]));
    }

    private static NodeEndpoint parseSs(String body) {
        String name = fragmentName(body);
        String main = cut(body, '#', '?');
        String decoded = main;
        if (!main.contains("@")) {
            String candidate = decodeBase64Text(main);
            if (candidate != null) decoded = candidate;
        } else {
            int at = main.lastIndexOf('@');
            String user = main.substring(0, at);
            if (!user.contains(":")) {
                String decodedUser = decodeBase64Text(user);
                if (decodedUser != null) decoded = decodedUser + main.substring(at);
            }
        }
        return parseAuthority("ss", decoded + (name.isEmpty() ? "" : "#" + name));
    }

    private static NodeEndpoint parseAuthority(String scheme, String body) {
        String name = fragmentName(body);
        String main = cut(body, '#', '?');
        int at = main.lastIndexOf('@');
        if (at >= 0) main = main.substring(at + 1);
        String host;
        int port = 0;
        if (main.startsWith("[")) {
            int close = main.indexOf(']');
            if (close < 0) return null;
            host = main.substring(1, close);
            if (close + 1 < main.length() && main.charAt(close + 1) == ':') port = parsePort(main.substring(close + 2));
        } else {
            int colon = main.lastIndexOf(':');
            if (colon <= 0) return null;
            host = main.substring(0, colon);
            port = parsePort(main.substring(colon + 1));
        }
        host = cleanHost(host);
        if (host.isEmpty()) return null;
        return new NodeEndpoint(normalizeProtocol(scheme), cleanName(name), host, port);
    }

    private static void add(Report report, Set<String> seen, NodeEndpoint node) {
        if (report.nodes.size() >= MAX_NODES) {
            report.truncated = true;
            return;
        }
        if (node == null || node.host.isEmpty()) {
            report.rejected++;
            return;
        }
        String key = node.protocol + "|" + node.host.toLowerCase(Locale.ROOT) + "|" + node.port;
        if (!seen.add(key)) {
            report.duplicates++;
            return;
        }
        report.nodes.add(node);
        Integer count = report.protocols.get(node.protocol);
        report.protocols.put(node.protocol, count == null ? 1 : count + 1);
    }

    private static String decodeBase64Text(String value) {
        try {
            byte[] decoded = Base64Compat.decode(value.replaceAll("\\s", ""));
            if (decoded.length == 0) return null;
            String text = new String(decoded, StandardCharsets.UTF_8);
            int control = 0;
            for (int i = 0; i < text.length(); i++) {
                char c = text.charAt(i);
                if (c < 9 || (c > 13 && c < 32)) control++;
            }
            return control > Math.max(2, text.length() / 20) ? null : text;
        } catch (Exception ignored) {
            return null;
        }
    }

    private static boolean looksLikeBase64(String text) {
        return text.length() >= 20 && text.length() <= 8 * 1024 * 1024
                && text.replaceAll("\\s", "").matches("[A-Za-z0-9_+/=-]+");
    }

    private static boolean looksLikeSubscription(String text) {
        String lower = text.toLowerCase(Locale.ROOT);
        return lower.contains("://") || lower.contains("proxies:") || lower.contains("server:");
    }

    private static boolean looksLikeProxyUri(String body) {
        String main = cut(body, '#', '?');
        if (main.contains("@")) return true;
        int colon = main.lastIndexOf(':');
        return colon > 0 && parsePort(main.substring(colon + 1)) > 0;
    }

    private static boolean isSupportedScheme(String scheme) {
        return "vless".equals(scheme) || "trojan".equals(scheme) || "hysteria".equals(scheme)
                || "hysteria2".equals(scheme) || "hy2".equals(scheme) || "tuic".equals(scheme)
                || "socks".equals(scheme) || "socks5".equals(scheme)
                || "http".equals(scheme) || "https".equals(scheme);
    }

    private static String normalizeProtocol(String value) {
        String protocol = unquote(value).trim().toLowerCase(Locale.ROOT);
        if ("hy2".equals(protocol)) return "hysteria2";
        if ("socks".equals(protocol)) return "socks5";
        return protocol;
    }

    private static String fragmentName(String body) {
        int hash = body.indexOf('#');
        if (hash < 0 || hash + 1 >= body.length()) return "";
        String value = body.substring(hash + 1);
        int amp = value.indexOf('&');
        if (amp >= 0) value = value.substring(0, amp);
        return decodeUrl(value);
    }

    private static String queryValue(String text, String key) {
        Matcher matcher = Pattern.compile("(?:[?&])" + Pattern.quote(key) + "=([^&]+)").matcher(text);
        return matcher.find() ? decodeUrl(matcher.group(1)) : "";
    }

    private static String jsonString(String json, String key) {
        Matcher matcher = Pattern.compile(String.format(Locale.ROOT, JSON_STRING.pattern(), Pattern.quote(key))).matcher(json);
        return matcher.find() ? matcher.group(1).replace("\\\"", "\"").replace("\\/", "/") : "";
    }

    private static int jsonNumber(String json, String key) {
        Matcher matcher = Pattern.compile(String.format(Locale.ROOT, JSON_NUMBER.pattern(), Pattern.quote(key))).matcher(json);
        return matcher.find() ? parsePort(matcher.group(1)) : 0;
    }

    private static String inlineValue(String line, String key) {
        Matcher matcher = Pattern.compile(String.format(Locale.ROOT, INLINE_KEY.pattern(), Pattern.quote(key))).matcher(line);
        if (!matcher.find()) return "";
        for (int i = 1; i <= 3; i++) if (matcher.group(i) != null) return matcher.group(i).trim();
        return "";
    }

    private static String cleanHost(String value) {
        String host = unquote(decodeUrl(value)).trim();
        if (host.startsWith("[") && host.endsWith("]")) host = host.substring(1, host.length() - 1);
        if (host.endsWith(".")) host = host.substring(0, host.length() - 1);
        if (host.contains("/") || host.contains("\\") || host.contains("@") || host.contains(" ")) return "";
        return host;
    }

    private static String cleanName(String value) {
        String name = unquote(decodeUrl(value)).trim();
        return name.length() > 120 ? name.substring(0, 120) : name;
    }

    private static String stripYamlComment(String line) {
        boolean single = false, doub = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '\'' && !doub) single = !single;
            else if (c == '"' && !single && (i == 0 || line.charAt(i - 1) != '\\')) doub = !doub;
            else if (c == '#' && !single && !doub && (i == 0 || Character.isWhitespace(line.charAt(i - 1)))) return line.substring(0, i);
        }
        return line;
    }

    private static String unquote(String value) {
        if (value == null) return "";
        String out = value.trim();
        if (out.length() >= 2 && ((out.startsWith("\"") && out.endsWith("\""))
                || (out.startsWith("'") && out.endsWith("'")))) out = out.substring(1, out.length() - 1);
        return out.trim();
    }

    private static String trimLink(String value) {
        String out = value;
        while (!out.isEmpty() && ").,;，；]}>".indexOf(out.charAt(out.length() - 1)) >= 0) out = out.substring(0, out.length() - 1);
        return out;
    }

    private static String cut(String value, char... delimiters) {
        int end = value.length();
        for (char delimiter : delimiters) {
            int at = value.indexOf(delimiter);
            if (at >= 0 && at < end) end = at;
        }
        return value.substring(0, end);
    }

    private static String decodeUrl(String value) {
        try { return URLDecoder.decode(value, "UTF-8"); }
        catch (Exception ignored) { return value == null ? "" : value; }
    }

    private static int parsePort(String value) {
        try {
            String clean = unquote(value).replaceAll("[^0-9].*$", "");
            int port = Integer.parseInt(clean);
            return port >= 1 && port <= 65535 ? port : 0;
        } catch (Exception ignored) { return 0; }
    }

    private static int indentation(String line) {
        int count = 0;
        while (count < line.length() && Character.isWhitespace(line.charAt(count))) count++;
        return count;
    }

    private static String stripBom(String text) {
        return !text.isEmpty() && text.charAt(0) == '\uFEFF' ? text.substring(1) : text;
    }

    private static final class MutableNode {
        String protocol = "";
        String name = "";
        String host = "";
        int port;
    }
}
