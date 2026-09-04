package com.fool.ipbatch;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/** Detects only this app's public egress through Android's current default route. */
public final class ExitIpDetector {
    public static final class Report {
        public final List<String> ips = new ArrayList<>();
        public final Map<String, String> origins = new LinkedHashMap<>();
        public final List<String> errors = new ArrayList<>();
        public long checkedAt;
        public String agreement = "无成功来源";

        public String summary() {
            return "检测到出口 " + ips.size() + " 个；" + agreement + (errors.isEmpty() ? "" : "；失败源 " + errors.size())
                    + "；结果代表本应用当前系统默认路由";
        }
    }

    private static final String[][] SOURCES = new String[][] {
            {"ipify IPv4", "https://api.ipify.org?format=json", "ip"},
            {"ipify 双栈", "https://api64.ipify.org?format=json", "ip"},
            {"GeoJS 出口", "https://get.geojs.io/v1/ip.json", "ip"}
    };

    public Report detect(int timeoutMs) {
        Report report = new Report();
        report.checkedAt = System.currentTimeMillis();
        ExecutorService executor = Executors.newFixedThreadPool(3);
        List<Future<Observation>> futures = new ArrayList<>();
        for (final String[] source : SOURCES) futures.add(executor.submit(new Callable<Observation>() {
            @Override public Observation call() { return check(source, timeoutMs); }
        }));
        executor.shutdown();
        for (Future<Observation> future : futures) {
            try {
                Observation item = future.get();
                if (item.error != null) { report.errors.add(item.error); continue; }
                if (!report.ips.contains(item.ip)) report.ips.add(item.ip);
                String existing = report.origins.get(item.ip);
                report.origins.put(item.ip, existing == null ? item.detail : existing + "；" + item.detail);
            } catch (Exception e) {
                report.errors.add("出口源：" + safe(e));
            }
        }
        int succeeded = SOURCES.length - report.errors.size();
        report.agreement = report.ips.size() == 1 && succeeded > 1 ? succeeded + " 个成功来源一致"
                : report.ips.size() > 1 ? "来源不一致或 IPv4/IPv6 分流" : succeeded + " 个来源成功";
        return report;
    }

    private Observation check(String[] source, int timeoutMs) {
        long begin = System.currentTimeMillis();
        try {
            JSONObject json = new JSONObject(get(source[1], timeoutMs));
            String ip = IpParser.normalize(json.optString(source[2], ""));
            if (ip == null || !IpParser.isPublic(ip)) throw new Exception("未返回有效公网 IP");
            return new Observation(ip, source[0] + " · " + (System.currentTimeMillis() - begin) + " ms", null);
        } catch (Exception e) { return new Observation(null, null, source[0] + "：" + safe(e)); }
    }

    private String get(String address, int timeoutMs) throws Exception {
        HttpURLConnection connection = (HttpURLConnection) new URL(address).openConnection();
        try {
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(timeoutMs);
            connection.setReadTimeout(timeoutMs);
            connection.setInstanceFollowRedirects(false);
            connection.setUseCaches(false);
            connection.setRequestProperty("Accept", "application/json");
            connection.setRequestProperty("User-Agent", "IPBatchInspector/5.0 Android");
            int code = connection.getResponseCode();
            InputStream input = code >= 200 && code < 300 ? connection.getInputStream() : connection.getErrorStream();
            String body = read(input);
            if (code < 200 || code >= 300) throw new Exception("HTTP " + code);
            return body;
        } finally {
            connection.disconnect();
        }
    }

    private String read(InputStream input) throws Exception {
        if (input == null) return "";
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8))) {
            StringBuilder body = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                body.append(line);
                if (body.length() > 64 * 1024) throw new Exception("返回过大");
            }
            return body.toString();
        }
    }

    private String safe(Exception e) {
        String message = e.getMessage();
        if (message == null || message.trim().isEmpty()) return e.getClass().getSimpleName();
        return message.length() > 80 ? message.substring(0, 80) : message;
    }

    private static final class Observation {
        final String ip, detail, error;
        Observation(String ip, String detail, String error) { this.ip = ip; this.detail = detail; this.error = error; }
    }
}
