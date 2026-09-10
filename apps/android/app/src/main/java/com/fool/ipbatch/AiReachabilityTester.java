package com.fool.ipbatch;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class AiReachabilityTester {
    public interface Listener { void onCheck(Check check, int completed, int total); }

    public static final class Check {
        public String platform = "";
        public String surface = "";
        public String host = "";
        public String status = "";
        public String detail = "";
        public int httpCode;
        public long durationMs;
        public long checkedAt;

        public boolean receivedResponse() { return status.startsWith("已收到"); }
    }

    public static final class Report {
        public final List<Check> checks = Collections.synchronizedList(new ArrayList<Check>());
        public long startedAt;
        public long finishedAt;

        public String summary() {
            int responses = 0, review = 0, failed = 0;
            synchronized (checks) {
                for (Check check : checks) {
                    if (check.receivedResponse()) responses++;
                    else if (check.status.contains("观察到")) review++;
                    else failed++;
                }
            }
            return "完成 " + checks.size() + " 项 · 收到 HTTP 响应 " + responses
                    + " · 需人工复核 " + review + " · 传输失败 " + failed;
        }
    }

    private static final Endpoint[] ENDPOINTS = new Endpoint[]{
            new Endpoint("ChatGPT", "网页", "https://chatgpt.com/", false, ""),
            new Endpoint("OpenAI", "API", "https://api.openai.com/v1/models", true, ""),
            new Endpoint("Claude", "网页", "https://claude.ai/", false, ""),
            new Endpoint("Claude", "API", "https://api.anthropic.com/v1/models", true, "2023-06-01"),
            new Endpoint("Gemini", "网页", "https://gemini.google.com/app", false, ""),
            new Endpoint("Gemini", "API", "https://generativelanguage.googleapis.com/v1beta/models", true, ""),
            new Endpoint("Grok", "网页", "https://grok.com/", false, ""),
            new Endpoint("xAI", "API", "https://api.x.ai/v1/models", true, ""),
            new Endpoint("Google AI Studio", "网页", "https://aistudio.google.com/", false, ""),
            new Endpoint("Microsoft Copilot", "网页", "https://copilot.microsoft.com/", false, ""),
            new Endpoint("Perplexity", "网页", "https://www.perplexity.ai/", false, "")
    };

    public static int endpointCount() { return ENDPOINTS.length; }

    public Report testAll(final int timeoutMs, final Listener listener) {
        final Report report = new Report();
        report.startedAt = System.currentTimeMillis();
        final CountDownLatch latch = new CountDownLatch(ENDPOINTS.length);
        final int[] completed = new int[]{0};
        ExecutorService executor = Executors.newFixedThreadPool(6);
        for (final Endpoint endpoint : ENDPOINTS) executor.submit(new Runnable() { @Override public void run() {
            Check check = test(endpoint, timeoutMs);
            report.checks.add(check);
            int now;
            synchronized (completed) { now = ++completed[0]; }
            if (listener != null) listener.onCheck(check, now, ENDPOINTS.length);
            latch.countDown();
        }});
        executor.shutdown();
        try { latch.await(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        report.finishedAt = System.currentTimeMillis();
        return report;
    }

    private Check test(Endpoint endpoint, int timeoutMs) {
        Check out = new Check();
        out.platform = endpoint.platform; out.surface = endpoint.surface;
        long begin = System.currentTimeMillis();
        HttpURLConnection connection = null;
        try {
            URL url = new URL(endpoint.url);
            out.host = url.getHost();
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(timeoutMs); connection.setReadTimeout(timeoutMs);
            connection.setInstanceFollowRedirects(false); connection.setUseCaches(false);
            connection.setRequestProperty("Accept", endpoint.authProbe ? "application/json" : "text/html,application/xhtml+xml");
            connection.setRequestProperty("Accept-Encoding", "identity");
            connection.setRequestProperty("User-Agent", "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/131 Mobile Safari/537.36");
            if (!endpoint.anthropicVersion.isEmpty()) connection.setRequestProperty("anthropic-version", endpoint.anthropicVersion);
            int code = connection.getResponseCode();
            out.httpCode = code;
            InputStream input = code >= 200 && code < 400 ? connection.getInputStream() : connection.getErrorStream();
            String body = readLimited(input).toLowerCase(Locale.ROOT);
            classify(out, endpoint.authProbe, code, body, connection.getHeaderField("Location"));
        } catch (Exception e) {
            out.status = "网络失败";
            out.detail = safe(e);
        } finally {
            if (connection != null) connection.disconnect();
            out.durationMs = System.currentTimeMillis() - begin;
            out.checkedAt = System.currentTimeMillis();
        }
        return out;
    }

    private void classify(Check out, boolean authProbe, int code, String body, String location) {
        boolean geo = code == 451 || containsAny(body, "unsupported country", "unsupported_country",
                "not available in your country", "not available in your region", "country is not supported");
        if (geo) {
            out.status = "观察到地区提示";
            out.detail = "本次匿名 HTTP 响应含地区不可用文字；这是一次观测，不是该国家或该 IP 的永久结论";
            return;
        }
        if (code >= 200 && code < 300) {
            out.status = "已收到入口响应";
            out.detail = "HTTP " + code + "；只证明匿名入口返回内容，不证明登录或对话可用";
            return;
        }
        if (code >= 300 && code < 400) {
            out.status = "已收到跳转响应";
            out.detail = "HTTP " + code + " → " + hostOnly(location) + "；未跟随跳转，不能据此判断地区或登录结果";
            return;
        }
        boolean auth = containsAny(body, "api key", "api_key", "authentication", "unauthorized", "credentials", "permission_denied");
        if (authProbe && (code == 400 || code == 401 || (code == 403 && auth))) {
            out.status = "已收到鉴权响应";
            out.detail = "HTTP " + code + "；未发送 API Key，只能确认 API 前端作出了响应";
        } else if (code == 401) {
            out.status = "已收到登录要求"; out.detail = "HTTP 401；不等同于登录后的服务可用";
        } else if (code == 403) {
            out.status = "观察到拒绝/挑战"; out.detail = "HTTP 403；可能是地区、IP 风控、WAF 或机器人挑战，原因未证实";
        } else if (code == 429) {
            out.status = "已收到限流响应"; out.detail = "HTTP 429；入口响应了，但未验证账号或模型";
        } else if (code >= 500) {
            out.status = "已收到服务端异常"; out.detail = "HTTP " + code + "；不能归因为地区限制";
        } else {
            out.status = "观察到其他响应"; out.detail = "HTTP " + code + "；原因未证实";
        }
    }

    private String readLimited(InputStream input) throws Exception {
        if (input == null) return "";
        BufferedReader reader = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder();
        try {
            String line;
            while ((line = reader.readLine()) != null && out.length() < 65536) out.append(line).append('\n');
        } finally { reader.close(); }
        return out.toString();
    }

    private boolean containsAny(String body, String... values) {
        for (String value : values) if (body.contains(value)) return true;
        return false;
    }

    private String hostOnly(String location) {
        try { return new URL(location).getHost(); } catch (Exception ignored) { return "下一入口"; }
    }

    private String safe(Exception e) {
        String message = e.getMessage();
        if (message == null || message.trim().isEmpty()) return e.getClass().getSimpleName();
        return message.length() > 140 ? message.substring(0, 140) : message;
    }

    private static final class Endpoint {
        final String platform, surface, url, anthropicVersion;
        final boolean authProbe;
        Endpoint(String platform, String surface, String url, boolean authProbe, String anthropicVersion) {
            this.platform = platform; this.surface = surface; this.url = url;
            this.authProbe = authProbe; this.anthropicVersion = anthropicVersion;
        }
    }
}
