package com.fool.ipbatch;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.ProxyInfo;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;

public final class NetworkStateReader {
    private NetworkStateReader() {}

    public static String describe(Context context) {
        try {
            ConnectivityManager manager = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
            if (manager == null) return "系统网络服务不可用";
            Network network = manager.getActiveNetwork();
            if (network == null) return "没有活动的系统默认网络";
            NetworkCapabilities caps = manager.getNetworkCapabilities(network);
            LinkProperties links = manager.getLinkProperties(network);
            if (caps == null) return "活动网络存在，但能力信息不可用";
            List<String> transports = new ArrayList<>();
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) transports.add("VPN");
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) transports.add("Wi‑Fi");
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) transports.add("移动网络");
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) transports.add("以太网");
            if (transports.isEmpty()) transports.add("其他网络");
            StringBuilder out = new StringBuilder();
            out.append("系统默认路由：").append(IpResult.join(transports, " + "));
            out.append("；互联网能力 ").append(caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) ? "有" : "无");
            out.append("；系统验证 ").append(caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) ? "通过" : "未通过/未知");
            if (links != null) {
                if (links.getInterfaceName() != null) out.append("；接口 ").append(links.getInterfaceName());
                List<String> dns = new ArrayList<>();
                for (InetAddress address : links.getDnsServers()) dns.add(address.getHostAddress());
                if (!dns.isEmpty()) out.append("；DNS ").append(IpResult.join(dns, ", "));
                ProxyInfo proxy = links.getHttpProxy();
                if (proxy != null) out.append("；系统 HTTP 代理 ").append(proxy.getHost()).append(":").append(proxy.getPort());
            }
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                out.append("。本应用普通 HTTPS 请求将按此 VPN 默认路由发出，除非 VPN 排除了本应用或允许绕过");
            }
            return out.toString();
        } catch (SecurityException e) {
            return "缺少读取网络状态权限";
        } catch (Exception e) {
            return "网络状态读取失败：" + (e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
        }
    }
}
