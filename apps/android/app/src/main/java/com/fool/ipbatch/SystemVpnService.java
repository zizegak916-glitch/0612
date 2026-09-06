package com.fool.ipbatch;

import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.RouteInfo;
import android.net.VpnService;
import android.os.Build;
import android.os.IBinder;
import android.os.ParcelFileDescriptor;
import android.os.PowerManager;
import android.util.Log;

import java.net.InetAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import io.nekohasekai.libbox.BridgeOptions;
import io.nekohasekai.libbox.BridgeSession;
import io.nekohasekai.libbox.CommandServer;
import io.nekohasekai.libbox.CommandServerHandler;
import io.nekohasekai.libbox.ConnectionOwner;
import io.nekohasekai.libbox.InterfaceUpdateListener;
import io.nekohasekai.libbox.Libbox;
import io.nekohasekai.libbox.LocalDNSTransport;
import io.nekohasekai.libbox.NeighborUpdateListener;
import io.nekohasekai.libbox.NetworkInterfaceIterator;
import io.nekohasekai.libbox.OverrideOptions;
import io.nekohasekai.libbox.PlatformInterface;
import io.nekohasekai.libbox.PlatformUser;
import io.nekohasekai.libbox.RoutePrefix;
import io.nekohasekai.libbox.RoutePrefixIterator;
import io.nekohasekai.libbox.ShellSession;
import io.nekohasekai.libbox.StringIterator;
import io.nekohasekai.libbox.SystemProxyStatus;
import io.nekohasekai.libbox.TunOptions;
import io.nekohasekai.libbox.WIFIState;

/** A bounded, user-consented Android system VPN used only by explicit real-subscription tests. */
public final class SystemVpnService extends VpnService implements PlatformInterface, CommandServerHandler {
    public static final String ACTION_STOP = "com.fool.ipbatch.SYSTEM_VPN_STOP";
    public static final String ACTION_STATE = "com.fool.ipbatch.ADVANCED_STATE";
    private static final String ACTION_START = "com.fool.ipbatch.SYSTEM_VPN_START";
    private static final String CHANNEL = "system-vpn-tests";
    private static final int NOTIFICATION_ID = 9401;
    private static final AtomicReference<Request> PENDING = new AtomicReference<>();

    private volatile boolean cancelled;
    private volatile String latestReport = "";
    private CommandServer commandServer;
    private ParcelFileDescriptor tunDescriptor;
    private volatile long tunGeneration;
    private PowerManager.WakeLock wakeLock;
    private ConnectivityManager connectivity;
    private ConnectivityManager.NetworkCallback networkCallback;
    private InterfaceUpdateListener interfaceListener;

    public static void start(Context context, String subscriptionUrl, boolean allowPrivateSubscription,
                             String requestedNode, String customTargets, boolean openBrowser) {
        Request request = new Request(subscriptionUrl, allowPrivateSubscription, requestedNode, customTargets, openBrowser);
        if (!PENDING.compareAndSet(null, request)) throw new IllegalStateException("已有系统 VPN 请求等待启动");
        Intent intent = new Intent(context, SystemVpnService.class).setAction(ACTION_START);
        try {
            if (Build.VERSION.SDK_INT >= 26) context.startForegroundService(intent); else context.startService(intent);
        } catch (RuntimeException failure) {
            PENDING.compareAndSet(request, null);
            throw failure;
        }
    }

    @Override public void onCreate() {
        super.onCreate(); connectivity = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE); createChannel();
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_STOP.equals(intent.getAction())) { stopNow("用户停止系统 VPN"); return START_NOT_STICKY; }
        final Request request = PENDING.getAndSet(null);
        if (request == null || !ACTION_START.equals(intent == null ? "" : intent.getAction())) return START_NOT_STICKY;
        if (commandServer != null) { publish("已有真实测试正在运行", true); return START_NOT_STICKY; }
        cancelled = false; tunGeneration = 0; latestReport = ""; publish("正在下载并验证订阅（尚未建立 VPN）…", true);
        AdvancedReportStore.save(this, "real", "", "", true); broadcast();
        PowerManager manager = (PowerManager) getSystemService(POWER_SERVICE);
        if (manager != null) { wakeLock = manager.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "IPBatchInspector:real-test"); wakeLock.acquire(20 * 60 * 1000L); }
        new Thread(new Runnable() { @Override public void run() { runTest(request); } }, "ipbatch-system-vpn").start();
        return START_NOT_STICKY;
    }

    private void runTest(Request request) {
        String error = "";
        try {
            if (prepare(this) != null) throw new Exception("Android VPN 授权未完成");
            InspectorApplication.requireLibbox();
            SubscriptionDownloader.Download download = new SubscriptionDownloader().download(
                    request.subscriptionUrl, "Clash.Meta", 18000, request.allowPrivateSubscription);
            SingBoxConfigBuilder.Result converted = new SingBoxConfigBuilder().build(download.content, request.requestedNode);
            if (request.openBrowser && converted.plans.size() != 1) throw new Exception("打开真实对话页面时必须精确选择一个节点");
            RealRouteProbe probe = new RealRouteProbe(); List<RealRouteProbe.Target> targets = probe.targets(request.customTargets);
            StringBuilder report = new StringBuilder();
            report.append("订阅真实测试 · Android 内嵌系统 VPN\n")
                    .append("libbox/sing-box：").append(Libbox.version()).append("\n")
                    .append("订阅：").append(download.summary()).append("\n转换：").append(converted.summary()).append("\n")
                    .append("安全边界：订阅在 TUN 建立前下载；节点服务器解析到私网/保留地址即拒绝；普通订阅体检不会调用本服务。\n")
                    .append("观测边界：未携带 Cookie、账号、API Key 或提示词。HTTP 403 不自动等同地区封锁。\n");
            for (String warning : converted.warnings) report.append("转换警告：").append(warning).append("\n");
            ExitIpDetector.Report baseline = new ExitIpDetector().detect(9000);
            report.append("建立 VPN 前本应用出口：")
                    .append(baseline.ips.isEmpty() ? baseline.summary() : IpResult.join(baseline.ips, ", ") + "；" + baseline.agreement)
                    .append("\n");
            commandServer = new CommandServer(this, this); commandServer.start();
            int index = 0;
            for (SingBoxConfigBuilder.Plan plan : converted.plans) {
                if (cancelled) throw new Exception("测试已取消"); index++;
                publish("系统 VPN 正在测试 " + index + "/" + converted.plans.size() + "：" + clip(plan.label, 50), true);
                Libbox.checkConfig(plan.config);
                long generationBefore = tunGeneration;
                commandServer.startOrReloadService(plan.config, new OverrideOptions());
                if (generationBefore == 0) awaitFirstTun(generationBefore);
                else Thread.sleep(1600L);
                if (cancelled) throw new Exception("sing-box 服务在节点启动阶段停止");
                ExitIpDetector.Report exit = new ExitIpDetector().detect(9000);
                report.append("\n【节点 ").append(index).append("】").append(plan.label).append(" [").append(plan.protocol).append("]\n")
                        .append("出口：").append(exit.ips.isEmpty() ? exit.summary() : IpResult.join(exit.ips, ", ") + "；" + exit.agreement).append("\n");
                if (exit.ips.isEmpty()) report.append("路由校验：未知；出口源全部失败，不能证明节点出口。\n");
                else if (overlaps(exit.ips, baseline.ips)) report.append("路由校验：与建 VPN 前出口重合；可能是同出口，也可能存在直连，不能标成已验证换路。\n");
                else report.append("路由校验：与建 VPN 前出口不同。\n");
                for (RealRouteProbe.Target target : targets) {
                    if (cancelled) throw new Exception("测试已取消"); report.append(probe.probe(target, 12000)).append("\n");
                }
            }
            report.append("\n真实性说明：reachable 只证明该节点下对话网址返回可接受的 HTTP 响应；登录、账号地区、模型配额和发消息能力仍需用户会话验证。\n")
                    .append("时间：").append(new java.util.Date()).append("；测试后默认拆除 TUN。\n");
            latestReport = report.toString();
            if (request.openBrowser) {
                report.append("浏览器验证模式：当前节点的系统 VPN 保持运行；通知栏点击“停止 VPN”后才拆除。\n");
                latestReport = report.toString(); AdvancedReportStore.save(this, "real", latestReport, "", true); broadcast();
                openTargets(targets); publish("浏览器验证中 · 当前系统 VPN 保持运行", true); releaseWakeLock(); return;
            }
        } catch (Throwable failure) { error = safe(failure); }
        if (!error.isEmpty()) latestReport = latestReport.isEmpty() ? "" : latestReport + "\n中止：" + error;
        AdvancedReportStore.save(this, "real", latestReport, error, false); broadcast();
        closeCore(); releaseWakeLock();
        publish(error.isEmpty() ? "真实测试完成，点击查看报告" : "真实测试失败：" + clip(error, 100), false);
        stopSelf();
    }

    private void awaitFirstTun(long previousGeneration) throws Exception {
        long deadline = System.currentTimeMillis() + 12000L;
        while (!cancelled && tunGeneration <= previousGeneration && System.currentTimeMillis() < deadline) Thread.sleep(100L);
        if (cancelled) throw new Exception("sing-box 在 TUN 建立前停止");
        if (tunGeneration <= previousGeneration || tunDescriptor == null) throw new Exception("12 秒内未收到 libbox 的 TUN 建立请求");
        Thread.sleep(500L);
    }

    private boolean overlaps(List<String> one, List<String> two) {
        for (String value : one) if (two.contains(value)) return true;
        return false;
    }

    private void openTargets(List<RealRouteProbe.Target> targets) {
        for (RealRouteProbe.Target target : targets) {
            try { startActivity(new Intent(Intent.ACTION_VIEW, android.net.Uri.parse(target.url)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)); }
            catch (Exception ignored) { }
        }
    }

    private synchronized void stopNow(String reason) {
        cancelled = true; closeCore(); releaseWakeLock();
        AdvancedReportStore.State state = AdvancedReportStore.load(this);
        String report = state.report == null ? latestReport : state.report;
        if (!report.isEmpty()) report += "\n系统 VPN 已停止：" + reason;
        AdvancedReportStore.save(this, "real", report, "", false); broadcast();
        if (Build.VERSION.SDK_INT >= 24) stopForeground(STOP_FOREGROUND_REMOVE); else stopForeground(true); stopSelf();
    }

    private synchronized void closeCore() {
        if (commandServer != null) {
            try { commandServer.closeService(); } catch (Exception ignored) { }
            try { commandServer.close(); } catch (Exception ignored) { }
            commandServer = null;
        }
        if (tunDescriptor != null) { try { tunDescriptor.close(); } catch (Exception ignored) { } tunDescriptor = null; }
        if (networkCallback != null && connectivity != null) { try { connectivity.unregisterNetworkCallback(networkCallback); } catch (Exception ignored) { } networkCallback = null; }
        interfaceListener = null;
    }

    @Override public void onRevoke() { stopNow("Android 撤销 VPN 授权"); super.onRevoke(); }
    @Override public void onDestroy() { closeCore(); releaseWakeLock(); super.onDestroy(); }
    @Override public IBinder onBind(Intent intent) { return super.onBind(intent); }

    @Override public int openTun(TunOptions options) throws Exception {
        if (prepare(this) != null) throw new Exception("Android VPN 授权失效");
        Builder builder = new Builder().setSession("IP系统情报 · 临时真实测试").setMtu(options.getMTU());
        if (Build.VERSION.SDK_INT >= 29) builder.setMetered(false);
        boolean has4 = addAddresses(builder, options.getInet4Address()); boolean has6 = addAddresses(builder, options.getInet6Address());
        if (options.getAutoRoute()) {
            boolean route4 = addRoutes(builder, options.getInet4RouteRange()); boolean route6 = addRoutes(builder, options.getInet6RouteRange());
            if (!route4 && has4) builder.addRoute("0.0.0.0", 0); if (!route6 && has6) builder.addRoute("::", 0);
            StringIterator dns = options.getDNSServerAddress(); while (dns != null && dns.hasNext()) builder.addDnsServer(dns.next());
            addApplications(builder, options.getIncludePackage(), true); addApplications(builder, options.getExcludePackage(), false);
        }
        ParcelFileDescriptor descriptor = builder.establish(); if (descriptor == null) throw new Exception("VpnService.Builder.establish() 返回空");
        ParcelFileDescriptor previous = tunDescriptor;
        tunDescriptor = descriptor; tunGeneration++;
        if (previous != null) try { previous.close(); } catch (Exception ignored) { }
        return descriptor.getFd();
    }

    private boolean addAddresses(Builder builder, RoutePrefixIterator values) throws Exception {
        boolean any = false; while (values != null && values.hasNext()) { RoutePrefix value = values.next(); builder.addAddress(value.address(), value.prefix()); any = true; } return any;
    }
    private boolean addRoutes(Builder builder, RoutePrefixIterator values) throws Exception {
        boolean any = false; while (values != null && values.hasNext()) { RoutePrefix value = values.next(); builder.addRoute(value.address(), value.prefix()); any = true; } return any;
    }
    private void addApplications(Builder builder, StringIterator values, boolean allowed) throws Exception {
        while (values != null && values.hasNext()) try { if (allowed) builder.addAllowedApplication(values.next()); else builder.addDisallowedApplication(values.next()); }
        catch (PackageManager.NameNotFoundException ignored) { }
    }

    @Override public boolean usePlatformAutoDetectInterfaceControl() { return true; }
    @Override public void autoDetectInterfaceControl(int fd) throws Exception { if (!protect(fd)) throw new Exception("VpnService.protect(fd) 失败，拒绝产生 VPN 回环"); }
    @Override public boolean useProcFS() { return Build.VERSION.SDK_INT < 29; }
    @Override public void startDefaultInterfaceMonitor(final InterfaceUpdateListener listener) throws Exception {
        interfaceListener = listener; if (connectivity == null) return;
        NetworkRequest request = new NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build();
        networkCallback = new ConnectivityManager.NetworkCallback() {
            @Override public void onAvailable(Network network) { updateInterface(network); }
            @Override public void onLinkPropertiesChanged(Network network, LinkProperties properties) { updateInterface(network); }
            @Override public void onLost(Network network) { if (interfaceListener != null) interfaceListener.updateDefaultInterface("", -1, false, false); }
        };
        connectivity.registerNetworkCallback(request, networkCallback);
        for (Network network : connectivity.getAllNetworks()) {
            NetworkCapabilities caps = connectivity.getNetworkCapabilities(network);
            if (caps != null && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) { updateInterface(network); break; }
        }
    }
    private void updateInterface(Network network) {
        try {
            LinkProperties links = connectivity.getLinkProperties(network); if (links == null || links.getInterfaceName() == null) return;
            NetworkInterface value = NetworkInterface.getByName(links.getInterfaceName()); int index = value == null ? -1 : value.getIndex();
            NetworkCapabilities caps = connectivity.getNetworkCapabilities(network);
            boolean expensive = caps != null && !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED);
            InterfaceUpdateListener listener = interfaceListener; if (listener != null) listener.updateDefaultInterface(links.getInterfaceName(), index, expensive, false);
        } catch (Exception ignored) { }
    }
    @Override public void closeDefaultInterfaceMonitor(InterfaceUpdateListener listener) {
        if (networkCallback != null && connectivity != null) try { connectivity.unregisterNetworkCallback(networkCallback); } catch (Exception ignored) { }
        networkCallback = null; interfaceListener = null;
    }
    @Override public NetworkInterfaceIterator getInterfaces() {
        List<io.nekohasekai.libbox.NetworkInterface> result = new ArrayList<>();
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces != null && interfaces.hasMoreElements()) {
                NetworkInterface system = interfaces.nextElement();
                io.nekohasekai.libbox.NetworkInterface item = new io.nekohasekai.libbox.NetworkInterface();
                item.setIndex(system.getIndex()); item.setMTU(system.getMTU()); item.setName(system.getName());
                int flags = 0;
                try { if (system.isUp()) flags |= 1; } catch (Exception ignored) { }
                for (InterfaceAddress address : system.getInterfaceAddresses()) if (address.getBroadcast() != null) { flags |= 2; break; }
                try { if (system.isLoopback()) flags |= 4; } catch (Exception ignored) { }
                try { if (system.isPointToPoint()) flags |= 8; } catch (Exception ignored) { }
                try { if (system.supportsMulticast()) flags |= 16; } catch (Exception ignored) { }
                if ((flags & 1) != 0) flags |= 32; // Go net.FlagRunning
                item.setFlags(flags);

                List<String> addresses = new ArrayList<>();
                for (InterfaceAddress address : system.getInterfaceAddresses()) {
                    InetAddress value = address.getAddress(); if (value == null) continue;
                    String host = value.getHostAddress(); int zone = host.indexOf('%'); if (zone >= 0) host = host.substring(0, zone);
                    addresses.add(host + "/" + address.getNetworkPrefixLength());
                }
                LinkProperties links = linkPropertiesFor(system.getName());
                List<String> dns = new ArrayList<>(); List<String> gateways = new ArrayList<>();
                if (links != null) {
                    // LinkProperties is preferred over Java's interface list because
                    // it is the Android OS view used for DNS and routing decisions.
                    if (addresses.isEmpty()) for (LinkAddress address : links.getLinkAddresses()) addresses.add(address.toString());
                    for (InetAddress address : links.getDnsServers()) dns.add(address.getHostAddress());
                    for (RouteInfo route : links.getRoutes()) if (route.getGateway() != null) gateways.add(route.getGateway().getHostAddress());
                }
                item.setAddresses(new ListStrings(addresses)); item.setDNSServer(new ListStrings(dns)); item.setGateway(new ListStrings(gateways));
                NetworkCapabilities caps = capabilitiesFor(system.getName());
                int type = Libbox.InterfaceTypeOther;
                if (caps != null) {
                    if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) type = Libbox.InterfaceTypeWIFI;
                    else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) type = Libbox.InterfaceTypeCellular;
                    else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) type = Libbox.InterfaceTypeEthernet;
                    item.setMetered(!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED));
                }
                item.setType(type); result.add(item);
            }
        } catch (Exception failure) { Log.w("sing-box", "读取 Android 网络接口失败", failure); }
        return new ListNetworkInterfaces(result);
    }

    private LinkProperties linkPropertiesFor(String name) {
        if (connectivity == null || name == null) return null;
        for (Network network : connectivity.getAllNetworks()) {
            LinkProperties value = connectivity.getLinkProperties(network);
            if (value != null && name.equals(value.getInterfaceName())) return value;
        }
        return null;
    }

    private NetworkCapabilities capabilitiesFor(String name) {
        if (connectivity == null || name == null) return null;
        for (Network network : connectivity.getAllNetworks()) {
            LinkProperties value = connectivity.getLinkProperties(network);
            if (value != null && name.equals(value.getInterfaceName())) return connectivity.getNetworkCapabilities(network);
        }
        return null;
    }
    @Override public boolean underNetworkExtension() { return false; }
    @Override public boolean includeAllNetworks() { return false; }
    @Override public WIFIState readWIFIState() { return null; }
    @Override public LocalDNSTransport localDNSTransport() { return null; }
    @Override public void clearDNSCache() { }
    @Override public ConnectionOwner findConnectionOwner(int protocol, String sourceAddress, int sourcePort, String destinationAddress, int destinationPort) { return null; }
    @Override public void sendNotification(io.nekohasekai.libbox.Notification notification) { }
    @Override public void cancelNotification(String identifier, int typeID) { }
    @Override public void startNeighborMonitor(NeighborUpdateListener listener) { }
    @Override public void closeNeighborMonitor(NeighborUpdateListener listener) { }
    @Override public void registerMyInterface(String name) { }
    @Override public boolean usePlatformShell() { return false; }
    @Override public void checkPlatformShell() throws Exception { throw new Exception("平台 Shell 已禁用"); }
    @Override public ShellSession openShellSession(PlatformUser user, String command, StringIterator environ, String term, int rows, int cols) throws Exception { throw new Exception("平台 Shell 已禁用"); }
    @Override public PlatformUser lookupUser(String username) throws Exception { throw new Exception("用户查询已禁用"); }
    @Override public String lookupSFTPServer() throws Exception { throw new Exception("SFTP 已禁用"); }
    @Override public String readSystemSSHHostKey() throws Exception { throw new Exception("SSH 已禁用"); }
    @Override public String tailscaleHostname() { return Build.MANUFACTURER + " " + Build.MODEL; }
    @Override public boolean usePlatformBridge() { return false; }
    @Override public BridgeSession createBridge(BridgeOptions options) throws Exception { throw new Exception("平台网桥已禁用"); }

    @Override public void serviceStop() { cancelled = true; new Thread(new Runnable() { @Override public void run() { stopNow("sing-box 请求停止"); } }).start(); }
    @Override public void serviceReload() throws Exception { throw new Exception("临时测试不接受外部重载"); }
    @Override public SystemProxyStatus getSystemProxyStatus() { SystemProxyStatus status = new SystemProxyStatus(); status.setAvailable(false); status.setEnabled(false); return status; }
    @Override public void setSystemProxyEnabled(boolean enabled) throws Exception { throw new Exception("系统 HTTP 代理未启用"); }
    @Override public void triggerNativeCrash() { }
    @Override public void writeDebugMessage(String message) { Log.d("sing-box", message == null ? "" : message); }
    @Override public int connectSSHAgent() { return -1; }

    private void publish(String text, boolean ongoing) {
        PendingIntent open = PendingIntent.getActivity(this, 91, new Intent(this, MainActivity.class), PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        PendingIntent stop = PendingIntent.getService(this, 92, new Intent(this, SystemVpnService.class).setAction(ACTION_STOP), PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        android.app.Notification.Builder builder = Build.VERSION.SDK_INT >= 26 ? new android.app.Notification.Builder(this, CHANNEL) : new android.app.Notification.Builder(this);
        android.app.Notification notification = builder.setSmallIcon(android.R.drawable.stat_sys_upload).setContentTitle("IP系统情报 · 系统 VPN")
                .setContentText(text).setContentIntent(open).setOngoing(ongoing).setOnlyAlertOnce(true)
                .addAction(new android.app.Notification.Action.Builder(null, "停止 VPN", stop).build()).build();
        if (ongoing) {
            if (Build.VERSION.SDK_INT >= 34) startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED);
            else startForeground(NOTIFICATION_ID, notification);
        } else {
            if (Build.VERSION.SDK_INT >= 24) stopForeground(STOP_FOREGROUND_DETACH); else stopForeground(false);
            NotificationManager manager = (NotificationManager) getSystemService(NOTIFICATION_SERVICE); if (manager != null) manager.notify(NOTIFICATION_ID, notification);
        }
    }
    private void createChannel() { if (Build.VERSION.SDK_INT >= 26) { NotificationManager manager = (NotificationManager) getSystemService(NOTIFICATION_SERVICE); if (manager != null) manager.createNotificationChannel(new NotificationChannel(CHANNEL, "临时系统 VPN 真实测试", NotificationManager.IMPORTANCE_LOW)); } }
    private void broadcast() { sendBroadcast(new Intent(ACTION_STATE).setPackage(getPackageName())); }
    private void releaseWakeLock() { if (wakeLock != null && wakeLock.isHeld()) try { wakeLock.release(); } catch (Exception ignored) { } wakeLock = null; }
    private static String safe(Throwable error) { String value = error.getMessage(); if (value == null || value.trim().isEmpty()) value = error.getClass().getSimpleName(); value = value.replace('\n', ' ').replace('\r', ' '); return clip(value, 900); }
    private static String clip(String value, int max) { if (value == null) return ""; return value.length() <= max ? value : value.substring(0, max); }

    private static final class Request {
        final String subscriptionUrl, requestedNode, customTargets; final boolean allowPrivateSubscription, openBrowser;
        Request(String subscriptionUrl, boolean allowPrivateSubscription, String requestedNode, String customTargets, boolean openBrowser) {
            this.subscriptionUrl = subscriptionUrl; this.allowPrivateSubscription = allowPrivateSubscription;
            this.requestedNode = requestedNode == null ? "" : requestedNode; this.customTargets = customTargets == null ? "" : customTargets;
            this.openBrowser = openBrowser;
        }
    }
    private static final class ListNetworkInterfaces implements NetworkInterfaceIterator {
        private final List<io.nekohasekai.libbox.NetworkInterface> values; private int index;
        ListNetworkInterfaces(List<io.nekohasekai.libbox.NetworkInterface> values) { this.values = values; }
        @Override public boolean hasNext() { return index < values.size(); }
        @Override public io.nekohasekai.libbox.NetworkInterface next() { return values.get(index++); }
    }
    private static final class ListStrings implements StringIterator {
        private final List<String> values; private int index;
        ListStrings(List<String> values) { this.values = values; }
        @Override public boolean hasNext() { return index < values.size(); }
        @Override public int len() { return values.size(); }
        @Override public String next() { return values.get(index++); }
    }
}
