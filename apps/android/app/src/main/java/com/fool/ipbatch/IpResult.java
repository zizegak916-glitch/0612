package com.fool.ipbatch;

import java.util.ArrayList;
import java.util.List;

public final class IpResult {
    public final String ip;
    public String origin = "";
    public String status = "等待";
    public Integer riskScore;
    public String riskSource = "";
    public String country = "";
    public String countryCode = "";
    public String region = "";
    public String city = "";
    public String asn = "";
    public String org = "";
    public String networkType = "";
    public String coordinates = "";
    public String timezone = "";
    public String registration = "";
    public String routing = "";
    public String freshness = "";
    public boolean vpn;
    public boolean proxy;
    public boolean tor;
    public boolean datacenter;
    public boolean abuser;
    public boolean mobile;
    public boolean riskEvaluated;
    public Boolean nativeIp;
    public int successfulSources;
    public long startedAt;
    public long finishedAt;
    public final List<String> sourceDetails = new ArrayList<>();
    public final List<String> sourceEvidence = new ArrayList<>();
    public final List<String> errors = new ArrayList<>();

    public IpResult(String ip) {
        this.ip = ip;
    }

    public void acceptRisk(int score, String source) {
        int bounded = Math.max(0, Math.min(100, score));
        if (riskScore == null || bounded > riskScore) {
            riskScore = bounded;
            riskSource = source;
        }
    }

    public void finish() {
        finishedAt = System.currentTimeMillis();
        if ("私网/保留".equals(status) || "已取消".equals(status)) return;
        if (successfulSources == 0) {
            status = "失败";
            return;
        }
        if ((riskScore != null && riskScore >= 67) || tor || proxy || vpn || abuser) {
            status = "高风险";
        } else if ((riskScore != null && riskScore >= 34) || datacenter) {
            status = "需注意";
        } else if (!riskEvaluated) {
            status = "信息可用";
        } else {
            status = "低风险";
        }
    }

    public String detailText() {
        List<String> parts = new ArrayList<>();
        addIfPresent(parts, coordinates.isEmpty() ? "" : "坐标 " + coordinates);
        addIfPresent(parts, timezone.isEmpty() ? "" : "时区 " + timezone);
        return parts.isEmpty() ? "无补充地理字段" : join(parts, " · ");
    }

    public long durationMs() {
        if (startedAt <= 0 || finishedAt <= 0) return 0;
        return Math.max(0, finishedAt - startedAt);
    }

    public String flagsText() {
        List<String> flags = new ArrayList<>();
        if (vpn) flags.add("VPN");
        if (proxy) flags.add("代理");
        if (tor) flags.add("Tor");
        if (datacenter) flags.add("机房");
        if (abuser) flags.add("滥用记录");
        if (mobile) flags.add("移动网络");
        if (nativeIp != null) flags.add(nativeIp ? "原生IP" : "广播IP");
        if (flags.isEmpty()) return "未发现显著风险标记";
        return join(flags, " · ");
    }

    public String locationText() {
        List<String> parts = new ArrayList<>();
        addIfPresent(parts, country);
        addIfPresent(parts, region);
        addIfPresent(parts, city);
        return parts.isEmpty() ? "位置未知" : join(parts, " / ");
    }

    public String networkText() {
        List<String> parts = new ArrayList<>();
        addIfPresent(parts, asn);
        addIfPresent(parts, org);
        addIfPresent(parts, networkType);
        return parts.isEmpty() ? "网络信息未知" : join(parts, " · ");
    }

    private static void addIfPresent(List<String> list, String value) {
        if (value != null && !value.trim().isEmpty() && !list.contains(value.trim())) {
            list.add(value.trim());
        }
    }

    public static String join(List<String> values, String separator) {
        StringBuilder out = new StringBuilder();
        for (String value : values) {
            if (out.length() > 0) out.append(separator);
            out.append(value);
        }
        return out.toString();
    }
}
