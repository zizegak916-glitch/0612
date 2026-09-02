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

/** Detects only this app's public egress through Android's current default route. */
public final class ExitIpDetector {
    public static final class Report {
        public final List<String> ips = new ArrayList<>();
        public final Map<String, String> origins = new LinkedHashMap<>();
        public final List<String> errors = new ArrayList<>();
        public long checkedAt;

        public String summary() {
            return "检测到出口 " + ips.size() + " 个" + (errors.isEmpty() ? "" : "；失败源 " + errors.size())
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
        for (String[] source : SOURCES) {
            long begin = System.currentTimeMillis();
            try {
                JSONObject json = new JSONObject(get(source[1], timeoutMs));
                String ip = IpParser.normalize(json.optString(source[2], ""));
                if (ip == null || !IpParser.isPublic(ip)) throw new Exception("未返回有效公网 IP");
                if (!report.ips.contains(ip)) report.ips.add(ip);
                String detail = source[0] + " · " + (System.currentTimeMillis() - begin) + " ms";
                String existing = report.origins.get(ip);
                report.origins.put(ip, existing == null ? detail : existing + "；" + detail);
            } catch (Exception e) {
                report.errors.add(source[0] + "：" + safe(e));
            }
        }
        return report;
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
            connection.setRequestProperty("User-Agent", "IPBatchInspector/2.0 Android");
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
}
