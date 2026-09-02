package com.fool.ipbatch;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Resolves node host names to addresses. It performs DNS only and never connects to node ports. */
public final class SubscriptionResolver {
    public static final int MAX_UNIQUE_IPS = 500;

    public static final class Report {
        public final List<String> ips = new ArrayList<>();
        public final Map<String, String> origins = new LinkedHashMap<>();
        public final List<String> unresolved = new ArrayList<>();
        public int literalHosts;
        public int domainHosts;
        public int privateAddresses;
        public int dnsAddresses;
        public boolean truncated;

        public String summary() {
            return "唯一公网 IP " + ips.size() + "；IP 节点 " + literalHosts + "；域名节点 " + domainHosts
                    + "；DNS 返回地址 " + dnsAddresses
                    + (unresolved.isEmpty() ? "" : "；解析失败 " + unresolved.size())
                    + (privateAddresses == 0 ? "" : "；本地拦截 " + privateAddresses)
                    + (truncated ? "；已达到 500 个 IP 上限" : "");
        }
    }

    private SubscriptionResolver() {}

    public static Report resolve(List<SubscriptionParser.NodeEndpoint> nodes) {
        Report report = new Report();
        Set<String> unique = new LinkedHashSet<>();
        Map<String, Integer> perHost = new LinkedHashMap<>();
        for (SubscriptionParser.NodeEndpoint node : nodes) {
            if (report.truncated) break;
            String literal = IpParser.normalize(node.host);
            if (literal != null) {
                report.literalHosts++;
                accept(literal, node, report, unique);
                continue;
            }
            report.domainHosts++;
            Integer seen = perHost.get(node.host);
            if (seen != null) {
                mergeExistingOrigin(node.host, node, report);
                continue;
            }
            perHost.put(node.host, 1);
            try {
                InetAddress[] addresses = InetAddress.getAllByName(node.host);
                if (addresses.length == 0) throw new Exception("没有 DNS 结果");
                for (InetAddress address : addresses) {
                    String normalized = IpParser.normalize(address.getHostAddress());
                    if (normalized == null) continue;
                    report.dnsAddresses++;
                    accept(normalized, node, report, unique);
                }
            } catch (Exception e) {
                if (report.unresolved.size() < 80) report.unresolved.add(node.label() + "：" + safe(e));
            }
        }
        report.ips.addAll(unique);
        return report;
    }

    private static void accept(String ip, SubscriptionParser.NodeEndpoint node, Report report, Set<String> unique) {
        if (!IpParser.isPublic(ip)) {
            report.privateAddresses++;
            return;
        }
        if (!unique.contains(ip) && unique.size() >= MAX_UNIQUE_IPS) {
            report.truncated = true;
            return;
        }
        unique.add(ip);
        String label = node.label();
        String existing = report.origins.get(ip);
        if (existing == null) report.origins.put(ip, label);
        else if (!existing.contains(label)) {
            int count = existing.split("\\n").length;
            if (count < 6) report.origins.put(ip, existing + "\n" + label);
            else if (!existing.endsWith("…更多节点")) report.origins.put(ip, existing + "\n…更多节点");
        }
    }

    private static void mergeExistingOrigin(String host, SubscriptionParser.NodeEndpoint node, Report report) {
        for (Map.Entry<String, String> entry : report.origins.entrySet()) {
            if (entry.getValue().contains(" @ " + host)) {
                String value = entry.getValue();
                if (!value.contains(node.label()) && value.split("\\n").length < 6) entry.setValue(value + "\n" + node.label());
            }
        }
    }

    private static String safe(Exception e) {
        String message = e.getMessage();
        if (message == null || message.trim().isEmpty()) return e.getClass().getSimpleName();
        return message.length() > 80 ? message.substring(0, 80) : message;
    }
}
