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
    public String confidence = "未知";
    public String signalSummary = "风险信号未知";
    public boolean vpn;
    public boolean proxy;
    public boolean tor;
    public boolean datacenter;
    public boolean abuser;
    public boolean mobile;
    public boolean riskEvaluated;
    public Boolean nativeIp;
    public int successfulSources;
    public int countryAgreement;
    public int asnAgreement;
    public long startedAt;
    public long finishedAt;
    public final List<String> sourceDetails = new ArrayList<>();
    public final List<String> sourceEvidence = new ArrayList<>();
    public final List<String> errors = new ArrayList<>();
    public final List<String> conflicts = new ArrayList<>();
    public final List<String> signalEvidence = new ArrayList<>();

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
            confidence = "无可用来源";
            return;
        }
        boolean importantConflict = false;
        for (String conflict : conflicts) {
            if (conflict.startsWith("国家代码") || conflict.startsWith("ASN")) importantConflict = true;
        }
        confidence = successfulSources >= 3 && !importantConflict && countryAgreement >= 2 && asnAgreement >= 2
                ? "高（至少三源，国家/ASN 均至少双源一致）"
                : successfulSources >= 2 ? "中（多源可用，请查看冲突）" : "低（仅单源可用）";
        signalSummary = summarizeSignals();
        if ((riskScore != null && riskScore >= 67) || tor || proxy || vpn || abuser) {
            status = "高风险";
        } else if ((riskScore != null && riskScore >= 34) || datacenter) {
            status = "需注意";
        } else if (!riskEvaluated || !allRiskSignalsObserved()) {
            status = "信息可用";
        } else {
            status = "低风险";
        }
    }

    public void mergeFrom(IpResult other, String source) {
        country = mergeField("国家", country, other.country, source);
        countryCode = mergeField("国家代码", countryCode, other.countryCode, source);
        region = mergeField("地区", region, other.region, source);
        city = mergeField("城市", city, other.city, source);
        asn = mergeField("ASN", asn, other.asn, source);
        org = mergeField("组织", org, other.org, source);
        networkType = mergeField("网络类型", networkType, other.networkType, source);
        if (coordinates.isEmpty()) coordinates = other.coordinates;
        if (timezone.isEmpty()) timezone = other.timezone;
        if (registration.isEmpty()) registration = other.registration;
        if (routing.isEmpty()) routing = other.routing;
        if (!other.freshness.isEmpty()) freshness = freshness.isEmpty() ? other.freshness : freshness + "；" + other.freshness;
        vpn |= other.vpn; proxy |= other.proxy; tor |= other.tor; datacenter |= other.datacenter;
        abuser |= other.abuser; mobile |= other.mobile; riskEvaluated |= other.riskEvaluated;
        if (other.nativeIp != null) nativeIp = other.nativeIp;
        if (other.riskScore != null) acceptRisk(other.riskScore, other.riskSource);
        successfulSources += other.successfulSources;
        sourceDetails.addAll(other.sourceDetails); sourceEvidence.addAll(other.sourceEvidence); errors.addAll(other.errors);
        signalEvidence.addAll(other.signalEvidence);
    }

    private String summarizeSignals() {
        List<String> summaries = new ArrayList<>();
        for (String flag : new String[]{"proxy", "vpn", "tor", "datacenter", "abuser"}) {
            int positive = 0, negative = 0;
            for (String item : signalEvidence) {
                if (item.contains("|" + flag + "=true")) positive++;
                if (item.contains("|" + flag + "=false")) negative++;
            }
            String state = positive > 0 && negative > 0 ? "矛盾" : positive >= 2 || ("tor".equals(flag) && positive > 0)
                    ? "确认" : positive > 0 ? "单源报告" : negative > 0 ? "未报" : "未知";
            summaries.add(flag + "=" + state + "(+" + positive + "/-" + negative + ")");
        }
        return join(summaries, " · ");
    }

    private boolean allRiskSignalsObserved() {
        for (String flag : new String[]{"proxy", "vpn", "tor", "datacenter", "abuser"}) {
            boolean observed = false;
            for (String item : signalEvidence) if (item.contains("|" + flag + "=")) { observed = true; break; }
            if (!observed) return false;
        }
        return true;
    }

    private String mergeField(String label, String current, String incoming, String source) {
        if (incoming == null || incoming.trim().isEmpty()) return current;
        if (current == null || current.trim().isEmpty()) return incoming.trim();
        if (!current.trim().equalsIgnoreCase(incoming.trim())) {
            String note = label + "：" + current.trim() + " ↔ " + incoming.trim() + "（" + source + "）";
            if (!conflicts.contains(note)) conflicts.add(note);
        }
        return current;
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
