package com.fool.ipbatch;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/** Separates IP literals exposed by a subscription from domain DNS observations. */
public final class SubscriptionResolver {
    public static final int MAX_UNIQUE_IPS = 500;

    public static final class Report {
        public final List<String> ips = new ArrayList<>();
        public final Map<String, String> origins = new LinkedHashMap<>();
        public final Map<String, List<String>> dnsObservations = new LinkedHashMap<>();
        public final List<String> unresolved = new ArrayList<>();
        public int literalHosts;
        public int domainHosts;
        public int privateAddresses;
        public int dnsAddresses;
        public boolean truncated;

        public String summary() {
            return "原文直露公网 IP " + ips.size() + "；IP 字面量节点 " + literalHosts + "；仅域名节点 " + domainHosts
                    + "；DNS 入口观察地址 " + dnsAddresses + "（不作为节点或出口 IP 调查）"
                    + "；可从订阅证明的真实流量出口 0"
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
        Map<String, Future<DnsAnswer>> lookups = new LinkedHashMap<>();
        ExecutorService dnsPool = Executors.newFixedThreadPool(24);
        for (SubscriptionParser.NodeEndpoint node : nodes) {
            if (IpParser.normalize(node.host) != null || lookups.containsKey(node.host)) continue;
            final String host = node.host;
            lookups.put(host, dnsPool.submit(new Callable<DnsAnswer>() {
                @Override public DnsAnswer call() {
                    try { return new DnsAnswer(InetAddress.getAllByName(host), null); }
                    catch (Exception e) { return new DnsAnswer(new InetAddress[0], safe(e)); }
                }
            }));
        }
        dnsPool.shutdown();
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
            if (seen != null) continue;
            perHost.put(node.host, 1);
            try {
                DnsAnswer answer = lookups.get(node.host).get();
                if (answer.error != null) throw new Exception(answer.error);
                InetAddress[] addresses = answer.addresses;
                if (addresses.length == 0) throw new Exception("没有 DNS 结果");
                for (InetAddress address : addresses) {
                    String normalized = IpParser.normalize(address.getHostAddress());
                    if (normalized == null) continue;
                    if (!IpParser.isPublic(normalized)) { report.privateAddresses++; continue; }
                    List<String> observed = report.dnsObservations.get(node.host);
                    if (observed == null) { observed = new ArrayList<>(); report.dnsObservations.put(node.host, observed); }
                    if (!observed.contains(normalized)) { observed.add(normalized); report.dnsAddresses++; }
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

    private static String safe(Exception e) {
        String message = e.getMessage();
        if (message == null || message.trim().isEmpty()) return e.getClass().getSimpleName();
        return message.length() > 80 ? message.substring(0, 80) : message;
    }

    private static final class DnsAnswer {
        final InetAddress[] addresses;
        final String error;
        DnsAnswer(InetAddress[] addresses, String error) { this.addresses = addresses; this.error = error; }
    }
}
