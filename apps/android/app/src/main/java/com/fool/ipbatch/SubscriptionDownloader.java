package com.fool.ipbatch;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.nio.charset.StandardCharsets;

public final class SubscriptionDownloader {
    private static final int MAX_BYTES = 5 * 1024 * 1024;

    public static final class Download {
        public String content = "";
        public String finalHost = "";
        public String contentType = "";
        public String etag = "";
        public String lastModified = "";
        public String subscriptionUserInfo = "";
        public int bytes;
        public int redirects;
        public long fetchedAt;

        public String summary() {
            StringBuilder out = new StringBuilder();
            out.append("下载 ").append(bytes).append(" 字节；来源 ").append(finalHost);
            if (!contentType.isEmpty()) out.append("；类型 ").append(contentType);
            if (redirects > 0) out.append("；HTTPS 跳转 ").append(redirects).append(" 次");
            if (!lastModified.isEmpty()) out.append("；Last-Modified ").append(lastModified);
            if (!etag.isEmpty()) out.append("；ETag 已提供");
            if (!subscriptionUserInfo.isEmpty()) out.append("；订阅流量/到期信息已提供");
            return out.toString();
        }
    }

    public Download download(String address, String userAgent, int timeoutMs, boolean allowPrivate) throws Exception {
        String primary = address.trim();
        try {
            return downloadExact(primary, userAgent, timeoutMs, allowPrivate);
        } catch (Exception first) {
            String alternate = alternateFormatUrl(primary);
            if (alternate == null) throw first;
            try {
                return downloadExact(alternate, userAgent, timeoutMs, allowPrivate);
            } catch (Exception second) {
                throw new Exception("原格式失败：" + first.getMessage() + "；fsl64/fslyaml 替代格式失败：" + second.getMessage());
            }
        }
    }

    private Download downloadExact(String address, String userAgent, int timeoutMs, boolean allowPrivate) throws Exception {
        URL current = new URL(address.trim());
        Download result = new Download();
        for (int hop = 0; hop <= 4; hop++) {
            validate(current, allowPrivate);
            HttpURLConnection connection = (HttpURLConnection) current.openConnection();
            try {
                connection.setRequestMethod("GET");
                connection.setConnectTimeout(timeoutMs);
                connection.setReadTimeout(timeoutMs);
                connection.setInstanceFollowRedirects(false);
                connection.setUseCaches(false);
                connection.setRequestProperty("Accept", "text/plain, application/yaml, application/x-yaml, application/json, */*");
                connection.setRequestProperty("Accept-Encoding", "identity");
                connection.setRequestProperty("User-Agent", userAgent == null || userAgent.trim().isEmpty()
                        ? "Clash.Meta" : userAgent.trim());
                int code = connection.getResponseCode();
                if (code >= 300 && code < 400) {
                    String location = connection.getHeaderField("Location");
                    if (location == null || location.trim().isEmpty()) throw new Exception("订阅跳转缺少地址");
                    current = new URL(current, location);
                    result.redirects++;
                    continue;
                }
                InputStream input = code >= 200 && code < 300 ? connection.getInputStream() : connection.getErrorStream();
                byte[] bytes = read(input);
                if (code == 401 || code == 403) throw new Exception("订阅鉴权失败（HTTP " + code + "）");
                if (code == 429) throw new Exception("订阅服务已限流（HTTP 429）");
                if (code < 200 || code >= 300) throw new Exception("订阅下载失败（HTTP " + code + "）");
                result.content = new String(bytes, StandardCharsets.UTF_8);
                if (result.content.trim().isEmpty()) throw new Exception("订阅返回为空");
                result.bytes = bytes.length;
                result.finalHost = current.getHost();
                result.contentType = safeHeader(connection.getContentType());
                result.etag = safeHeader(connection.getHeaderField("ETag"));
                result.lastModified = safeHeader(connection.getHeaderField("Last-Modified"));
                result.subscriptionUserInfo = safeHeader(connection.getHeaderField("Subscription-Userinfo"));
                result.fetchedAt = System.currentTimeMillis();
                return result;
            } finally {
                connection.disconnect();
            }
        }
        throw new Exception("订阅跳转次数超过 4 次");
    }

    public static String alternateFormatUrl(String address) {
        if (address == null) return null;
        java.util.regex.Matcher matcher = java.util.regex.Pattern
                .compile("(?i)(^|/)(fsl64|fslyaml)(?=/|\\?|#|$)").matcher(address);
        if (!matcher.find()) return null;
        String replacement = "fsl64".equalsIgnoreCase(matcher.group(2)) ? "fslyaml" : "fsl64";
        return address.substring(0, matcher.start(2)) + replacement + address.substring(matcher.end(2));
    }

    private void validate(URL url, boolean allowPrivate) throws Exception {
        String protocol = url.getProtocol().toLowerCase();
        if (!"https".equals(protocol) && !"http".equals(protocol)) throw new Exception("订阅只允许 HTTP/HTTPS");
        if (url.getHost() == null || url.getHost().trim().isEmpty()) throw new Exception("订阅地址缺少主机名");
        if (url.getUserInfo() != null) throw new Exception("拒绝包含 URL 用户信息的订阅地址");
        InetAddress[] addresses = InetAddress.getAllByName(url.getHost());
        if (addresses.length == 0) throw new Exception("订阅域名无法解析");
        boolean hasPrivate = false, hasPublic = false;
        for (InetAddress address : addresses) {
            String normalized = IpParser.normalize(address.getHostAddress());
            if (normalized != null && IpParser.isPublic(normalized)) hasPublic = true;
            else hasPrivate = true;
        }
        if (hasPrivate && hasPublic) throw new Exception("域名同时解析到公网和私网，已按 DNS 重绑定风险拒绝");
        if (hasPrivate && !allowPrivate) throw new Exception("该订阅位于本机/局域网，请勾选允许访问私网订阅");
        if ("http".equals(protocol) && !hasPrivate) throw new Exception("公网订阅必须使用 HTTPS；HTTP 只允许明确授权的本机/局域网地址");
    }

    private byte[] read(InputStream input) throws Exception {
        if (input == null) return new byte[0];
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int read;
            while ((read = input.read(buffer)) >= 0) {
                if (read == 0) continue;
                if (out.size() + read > MAX_BYTES) throw new Exception("订阅内容超过 5 MiB 限制");
                out.write(buffer, 0, read);
            }
            return out.toByteArray();
        } finally {
            input.close();
        }
    }

    private String safeHeader(String value) {
        if (value == null) return "";
        String clean = value.replace('\n', ' ').replace('\r', ' ').trim();
        return clean.length() > 300 ? clean.substring(0, 300) : clean;
    }
}
