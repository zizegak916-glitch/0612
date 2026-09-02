package com.fool.ipbatch;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public final class IpParser {
    public static final int MAX_IPS = 500;

    public static final class ParseReport {
        public final List<String> ips = new ArrayList<>();
        public int rejected;
        public int duplicates;
        public int truncated;
        public int cidrCollapsed;
    }

    private IpParser() {}

    public static ParseReport parse(String text) {
        ParseReport report = new ParseReport();
        if (text == null || text.trim().isEmpty()) return report;
        String[] rawTokens = text.split("[\\s,;，；、]+", -1);
        Set<String> unique = new LinkedHashSet<>();
        for (String raw : rawTokens) {
            String candidate = clean(raw);
            if (candidate.isEmpty()) continue;
            int slash = candidate.indexOf('/');
            if (slash > 0 && candidate.substring(slash + 1).matches("\\d{1,3}")) {
                candidate = candidate.substring(0, slash);
                report.cidrCollapsed++;
            }
            String normalized = normalize(candidate);
            if (normalized == null) {
                report.rejected++;
                continue;
            }
            if (!unique.add(normalized)) report.duplicates++;
        }
        int index = 0;
        for (String ip : unique) {
            if (index++ < MAX_IPS) report.ips.add(ip);
            else report.truncated++;
        }
        return report;
    }

    private static String clean(String raw) {
        if (raw == null) return "";
        String value = raw.trim();
        while (!value.isEmpty() && "\"'([{<".indexOf(value.charAt(0)) >= 0) {
            if (value.charAt(0) == '[' && value.indexOf(']') > 0) break;
            value = value.substring(1);
        }
        while (!value.isEmpty() && "\"')]}>,。".indexOf(value.charAt(value.length() - 1)) >= 0) {
            value = value.substring(0, value.length() - 1);
        }
        String lower = value.toLowerCase(Locale.ROOT);
        if (lower.startsWith("http://")) value = value.substring(7);
        if (lower.startsWith("https://")) value = value.substring(8);
        int path = value.indexOf('/');
        if (path > 0 && !value.substring(path + 1).matches("\\d{1,3}")) value = value.substring(0, path);
        if (value.startsWith("[") && value.contains("]")) {
            value = value.substring(1, value.indexOf(']'));
        } else if (value.matches("\\d{1,3}(?:\\.\\d{1,3}){3}:\\d{1,5}")) {
            value = value.substring(0, value.lastIndexOf(':'));
        }
        return value.trim();
    }

    public static String normalize(String candidate) {
        if (candidate == null || candidate.isEmpty() || candidate.contains("%")) return null;
        if (isStrictIpv4(candidate)) {
            String[] parts = candidate.split("\\.");
            return Integer.parseInt(parts[0]) + "." + Integer.parseInt(parts[1]) + "." +
                    Integer.parseInt(parts[2]) + "." + Integer.parseInt(parts[3]);
        }
        if (!candidate.contains(":") || !candidate.matches("[0-9a-fA-F:.]+")) return null;
        try {
            InetAddress address = InetAddress.getByName(candidate);
            return address instanceof Inet6Address ? address.getHostAddress() : null;
        } catch (Exception ignored) {
            return null;
        }
    }

    private static boolean isStrictIpv4(String value) {
        String[] parts = value.split("\\.", -1);
        if (parts.length != 4) return false;
        for (String part : parts) {
            if (part.isEmpty() || part.length() > 3 || !part.matches("\\d+")) return false;
            if (part.length() > 1 && part.charAt(0) == '0') return false;
            int n;
            try { n = Integer.parseInt(part); } catch (NumberFormatException e) { return false; }
            if (n < 0 || n > 255) return false;
        }
        return true;
    }

    public static boolean isPublic(String ip) {
        try {
            InetAddress address = InetAddress.getByName(ip);
            if (address.isAnyLocalAddress() || address.isLoopbackAddress() || address.isLinkLocalAddress()
                    || address.isSiteLocalAddress() || address.isMulticastAddress()) return false;
            byte[] bytes = address.getAddress();
            if (address instanceof Inet4Address) {
                int a = bytes[0] & 255, b = bytes[1] & 255, c = bytes[2] & 255;
                if (a == 0 || a >= 224) return false;
                if (a == 100 && b >= 64 && b <= 127) return false;
                if (a == 192 && b == 0 && (c == 0 || c == 2)) return false;
                if (a == 198 && (b == 18 || b == 19)) return false;
                if (a == 198 && b == 51 && c == 100) return false;
                if (a == 203 && b == 0 && c == 113) return false;
            } else {
                if ((bytes[0] & 0xFE) == 0xFC) return false;
                if ((bytes[0] & 255) == 0x20 && (bytes[1] & 255) == 0x01
                        && (bytes[2] & 255) == 0x0d && (bytes[3] & 255) == 0xb8) return false;
            }
            return true;
        } catch (Exception ignored) {
            return false;
        }
    }
}
