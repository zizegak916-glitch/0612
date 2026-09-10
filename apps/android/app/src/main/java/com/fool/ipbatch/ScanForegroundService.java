package com.fool.ipbatch;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.graphics.Color;
import android.os.Build;
import android.os.IBinder;

import org.json.JSONObject;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicBoolean;

public final class ScanForegroundService extends Service {
    public static final String ACTION_START_SCAN = "com.fool.ipbatch.START_SCAN";
    public static final String ACTION_CANCEL_SCAN = "com.fool.ipbatch.CANCEL_SCAN";
    public static final String ACTION_SCAN_STATE = "com.fool.ipbatch.SCAN_STATE";
    public static final String ACTION_START_SUBSCRIPTION = "com.fool.ipbatch.START_SUBSCRIPTION";
    public static final String ACTION_SUBSCRIPTION_STATE = "com.fool.ipbatch.SUBSCRIPTION_STATE";
    public static final String ACTION_START_EXIT = "com.fool.ipbatch.START_EXIT";
    public static final String ACTION_EXIT_STATE = "com.fool.ipbatch.EXIT_STATE";
    public static final String EXTRA_IPS = "ips";
    public static final String EXTRA_ORIGINS = "origins";
    public static final String EXTRA_LABEL = "label";
    public static final String EXTRA_RESULT = "result";
    public static final String EXTRA_COMPLETED = "completed";
    public static final String EXTRA_TOTAL = "total";
    public static final String EXTRA_RUNNING = "running";
    public static final String EXTRA_CANCELLED = "cancelled";
    public static final String EXTRA_URL = "url";
    public static final String EXTRA_USER_AGENT = "user_agent";
    public static final String EXTRA_ALLOW_PRIVATE = "allow_private";
    public static final String EXTRA_SUBSCRIPTION_SUMMARY = "subscription_summary";
    public static final String EXTRA_SUBSCRIPTION_ERROR = "subscription_error";
    public static final String EXTRA_SUBSCRIPTION_READY = "subscription_ready";
    public static final String EXTRA_EXIT_SUMMARY = "exit_summary";
    public static final String EXTRA_EXIT_ERROR = "exit_error";

    private static final String CHANNEL = "system_scan";
    private static final int NOTIFICATION_ID = 7311;

    private final AtomicBoolean cancelled = new AtomicBoolean(false);
    private final Set<String> finishedIps = new HashSet<>();
    private final Map<String, IpResult> results = new LinkedHashMap<>();
    private final List<Future<?>> futures = new ArrayList<>();
    private final Object stateLock = new Object();
    private ExecutorService executor;
    private ScanStateStore.Snapshot snapshot;
    private boolean running;
    private boolean finishing;
    private boolean preparing;
    private String preparationKind = "";

    @Override public void onCreate() {
        super.onCreate();
        createChannel();
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? "" : intent.getAction();
        if (ACTION_CANCEL_SCAN.equals(action)) {
            cancelScan();
            return START_NOT_STICKY;
        }
        if (ACTION_START_SCAN.equals(action)) {
            promote("正在启动系统扫描服务…", 0, 0, true);
            beginScan(intent);
        } else if (ACTION_START_SUBSCRIPTION.equals(action)) {
            promote("正在后台下载并解析订阅…", 0, 0, true);
            beginSubscription(intent);
        } else if (ACTION_START_EXIT.equals(action)) {
            promote("正在后台识别当前设备出口…", 0, 0, true);
            beginExitDetection();
        }
        return START_NOT_STICKY;
    }

    @Override public IBinder onBind(Intent intent) { return null; }

    @Override public void onDestroy() {
        if (executor != null && !executor.isTerminated()) executor.shutdownNow();
        super.onDestroy();
    }

    private void beginScan(Intent intent) {
        ArrayList<String> ips = intent.getStringArrayListExtra(EXTRA_IPS);
        Map<String, String> origins = parseOrigins(intent.getStringExtra(EXTRA_ORIGINS));
        beginScanData(ips, origins, clean(intent.getStringExtra(EXTRA_LABEL), "手动输入"));
    }

    private void beginScanData(ArrayList<String> ips, Map<String, String> origins, String label) {
        synchronized (stateLock) {
            if (running) {
                broadcast(null);
                return;
            }
            if (ips == null || ips.isEmpty()) {
                completeNotification("没有可检测的 IP");
                stopSelf();
                return;
            }
            snapshot = new ScanStateStore.Snapshot();
            snapshot.label = clean(label, "手动输入");
            snapshot.running = true;
            snapshot.total = ips.size();
            snapshot.startedAt = System.currentTimeMillis();
            results.clear(); finishedIps.clear(); futures.clear();
            cancelled.set(false); finishing = false; preparing = false; preparationKind = ""; running = true;
            for (String ip : ips) {
                IpResult pending = new IpResult(ip);
                pending.origin = origins.containsKey(ip) ? origins.get(ip) : snapshot.label;
                results.put(ip, pending); snapshot.results.add(pending);
            }
            ScanStateStore.save(this, snapshot);
            broadcast(null);
            updateNotification();
            executor = Executors.newFixedThreadPool(ips.size() > 12 ? 4 : 3);
            final ApiClient.Settings settings = SettingsRepository.load(this);
            final ApiClient client = new ApiClient();
            final IpEvidenceCache cache = new IpEvidenceCache(this);
            for (final IpResult pending : new ArrayList<>(snapshot.results)) {
                futures.add(executor.submit(new Runnable() { @Override public void run() {
                    if (cancelled.get()) {
                        pending.status = "已取消";
                        finishResult(pending);
                        return;
                    }
                    IpResult done = cache.get(pending.ip, settings);
                    if (done == null) {
                        done = client.scan(pending.ip, settings);
                        cache.put(done, settings);
                    }
                    done.origin = pending.origin;
                    if (cancelled.get()) done.status = "已取消";
                    finishResult(done);
                }}));
            }
            executor.shutdown();
        }
    }

    private void beginSubscription(Intent intent) {
        synchronized (stateLock) {
            if (running || preparing) { broadcastSubscription("", "已有后台任务正在运行", false); return; }
            preparing = true; preparationKind = "subscription"; cancelled.set(false); SubscriptionSessionCache.clear();
        }
        final String url = intent.getStringExtra(EXTRA_URL);
        final String userAgent = intent.getStringExtra(EXTRA_USER_AGENT);
        final boolean allowPrivate = intent.getBooleanExtra(EXTRA_ALLOW_PRIVATE, false);
        new Thread(new Runnable() { @Override public void run() {
            try {
                SubscriptionDownloader.Download download = new SubscriptionDownloader().download(url, userAgent, 15000, allowPrivate);
                SubscriptionParser.Report parsed = SubscriptionParser.parse(download.content);
                List<String> providerUrls = new ArrayList<>(parsed.providerUrls);
                int providerOk = 0, providerFailed = 0;
                List<String> requestedProviders = new ArrayList<>();
                for (int i = 0; i < providerUrls.size() && i < 10; i++) if (!providerUrls.get(i).equals(url)) requestedProviders.add(providerUrls.get(i));
                ExecutorService providerPool = Executors.newFixedThreadPool(Math.max(1, Math.min(6, requestedProviders.size())));
                List<Future<SubscriptionDownloader.Download>> providerFutures = new ArrayList<>();
                for (final String providerUrl : requestedProviders) providerFutures.add(providerPool.submit(new Callable<SubscriptionDownloader.Download>() {
                    @Override public SubscriptionDownloader.Download call() throws Exception {
                        return new SubscriptionDownloader().download(providerUrl, userAgent, 12000, allowPrivate);
                    }
                }));
                providerPool.shutdown();
                for (Future<SubscriptionDownloader.Download> providerFuture : providerFutures) {
                    if (cancelled.get()) { providerFuture.cancel(true); continue; }
                    try {
                        SubscriptionDownloader.Download nested = providerFuture.get();
                        SubscriptionParser.merge(parsed, SubscriptionParser.parse(nested.content)); providerOk++;
                    } catch (Exception ignored) { providerFailed++; }
                }
                if (providerOk > 0 || providerFailed > 0) parsed.warnings.add("远程 Provider 读取成功 " + providerOk + "，失败 " + providerFailed);
                if (providerUrls.size() > 10) parsed.warnings.add("远程 Provider 超过 10 个，本次只读取前 10 个");
                SubscriptionResolver.Report resolved = SubscriptionResolver.resolve(parsed.nodes);
                if (cancelled.get()) throw new Exception("用户已取消订阅后台处理");
                StringBuilder detail = new StringBuilder(download.summary()).append("\n").append(parsed.summary())
                        .append("\n").append(resolved.summary())
                        .append("\n调查边界：只把订阅 server 字段直接写出的公网 IP 送入情报查询；域名 DNS 地址仅列为入口基础设施观察，中转、落地、链式和其他未暴露出口均不可观测。");
                if (!resolved.dnsObservations.isEmpty()) {
                    List<String> dnsLines = new ArrayList<>();
                    for (Map.Entry<String, List<String>> entry : resolved.dnsObservations.entrySet()) {
                        if (dnsLines.size() >= 20) break;
                        dnsLines.add(entry.getKey() + " → " + IpResult.join(entry.getValue(), ", "));
                    }
                    detail.append("\n域名 DNS 观察（不参与 IP 调查）：").append(IpResult.join(dnsLines, "；"));
                }
                if (!download.subscriptionUserInfo.isEmpty()) detail.append("\nSubscription-Userinfo：").append(download.subscriptionUserInfo);
                if (!parsed.warnings.isEmpty()) detail.append("\n提示：").append(IpResult.join(parsed.warnings, "；"));
                if (!resolved.unresolved.isEmpty()) detail.append("\n部分解析失败：")
                        .append(IpResult.join(limit(resolved.unresolved, 12), "；"));
                SubscriptionSessionCache.set(download.content, parsed.nodes);
                broadcastSubscription(detail.toString(), "", true);
                if (resolved.ips.isEmpty()) {
                    synchronized (stateLock) { preparing = false; }
                    completeNotification("订阅解析完成，但原文没有直接暴露公网 IP"); stopSelf(); return;
                }
                ArrayList<String> ips = new ArrayList<>(resolved.ips);
                beginScanData(ips, resolved.origins, "订阅 · " + parsed.nodes.size() + " 节点 · " + resolved.ips.size() + " 个原文直露公网 IP");
            } catch (Exception e) {
                synchronized (stateLock) { preparing = false; }
                broadcastSubscription("", safe(e), false); completeNotification("订阅处理失败"); stopSelf();
            }
        }}, "subscription-prepare").start();
    }

    private void beginExitDetection() {
        synchronized (stateLock) {
            if (running || preparing) { broadcastExit("", "已有后台任务正在运行"); return; }
            preparing = true; preparationKind = "exit"; cancelled.set(false);
        }
        new Thread(new Runnable() { @Override public void run() {
            ExitIpDetector.Report report = new ExitIpDetector().detect(12000);
            if (cancelled.get()) { broadcastExit("", "用户已取消出口识别"); return; }
            if (report.ips.isEmpty()) {
                synchronized (stateLock) { preparing = false; preparationKind = ""; }
                broadcastExit("", IpResult.join(report.errors, "；")); completeNotification("出口识别失败"); stopSelf(); return;
            }
            broadcastExit(report.summary(), "");
            beginScanData(new ArrayList<>(report.ips), report.origins, "当前出口 · " + report.summary());
        }}, "exit-detection").start();
    }

    private void broadcastSubscription(String summary, String error, boolean ready) {
        Intent state = new Intent(ACTION_SUBSCRIPTION_STATE).setPackage(getPackageName());
        state.putExtra(EXTRA_SUBSCRIPTION_SUMMARY, summary); state.putExtra(EXTRA_SUBSCRIPTION_ERROR, error);
        state.putExtra(EXTRA_SUBSCRIPTION_READY, ready); sendBroadcast(state);
    }

    private void broadcastExit(String summary, String error) {
        Intent state = new Intent(ACTION_EXIT_STATE).setPackage(getPackageName());
        state.putExtra(EXTRA_EXIT_SUMMARY, summary); state.putExtra(EXTRA_EXIT_ERROR, error); sendBroadcast(state);
    }

    private void finishResult(IpResult result) {
        boolean done;
        synchronized (stateLock) {
            if (!running || !finishedIps.add(result.ip)) return;
            results.put(result.ip, result);
            for (int i = 0; i < snapshot.results.size(); i++) {
                if (snapshot.results.get(i).ip.equals(result.ip)) {
                    snapshot.results.set(i, result);
                    break;
                }
            }
            snapshot.completed = finishedIps.size();
            snapshot.cancelled = cancelled.get();
            ScanStateStore.save(this, snapshot);
            done = snapshot.completed >= snapshot.total;
        }
        broadcast(result);
        updateNotification();
        if (done) finishRun();
    }

    private void cancelScan() {
        List<IpResult> pending = new ArrayList<>();
        synchronized (stateLock) {
            if (preparing && !running) {
                cancelled.set(true); preparing = false;
                if ("exit".equals(preparationKind)) broadcastExit("", "用户已取消出口识别");
                else broadcastSubscription("", "用户已取消订阅后台处理", false);
                preparationKind = "";
                if (Build.VERSION.SDK_INT >= 24) stopForeground(STOP_FOREGROUND_REMOVE); else stopForeground(true);
                stopSelf(); return;
            }
            if (!running || snapshot == null) {
                stopSelf();
                return;
            }
            cancelled.set(true);
            for (Future<?> future : futures) future.cancel(true);
            for (IpResult result : snapshot.results) {
                if (!finishedIps.contains(result.ip)) {
                    result.status = "已取消";
                    result.finishedAt = System.currentTimeMillis();
                    pending.add(result);
                }
            }
        }
        for (IpResult result : pending) finishResult(result);
    }

    private void finishRun() {
        synchronized (stateLock) {
            if (finishing || snapshot == null) return;
            finishing = true; running = false; snapshot.running = false;
            snapshot.cancelled = cancelled.get();
            ScanStateStore.save(this, snapshot);
            ScanHistoryStore.archive(this, snapshot);
        }
        broadcast(null);
        String text = snapshot.cancelled ? "扫描已取消，结果已保存" : "扫描完成：" + snapshot.completed + " 个 IP";
        if (Build.VERSION.SDK_INT >= 24) stopForeground(STOP_FOREGROUND_DETACH); else stopForeground(false);
        completeNotification(text);
        stopSelf();
    }

    private void broadcast(IpResult result) {
        Intent state = new Intent(ACTION_SCAN_STATE).setPackage(getPackageName());
        synchronized (stateLock) {
            state.putExtra(EXTRA_COMPLETED, snapshot == null ? 0 : snapshot.completed);
            state.putExtra(EXTRA_TOTAL, snapshot == null ? 0 : snapshot.total);
            state.putExtra(EXTRA_LABEL, snapshot == null ? "" : snapshot.label);
            state.putExtra(EXTRA_RUNNING, running);
            state.putExtra(EXTRA_CANCELLED, cancelled.get());
            if (result != null) try { state.putExtra(EXTRA_RESULT, ScanStateStore.encodeResult(result).toString()); }
            catch (Exception ignored) { }
        }
        sendBroadcast(state);
    }

    private void promote(String text, int completed, int total, boolean ongoing) {
        Notification notification = notification(text, completed, total, ongoing);
        if (Build.VERSION.SDK_INT >= 29) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC);
        } else {
            startForeground(NOTIFICATION_ID, notification);
        }
    }

    private void updateNotification() {
        ScanStateStore.Snapshot state;
        synchronized (stateLock) { state = snapshot; }
        if (state == null) return;
        String text = state.label + " · " + state.completed + "/" + state.total;
        NotificationManager manager = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (manager != null) manager.notify(NOTIFICATION_ID, notification(text, state.completed, state.total, true));
    }

    private void completeNotification(String text) {
        NotificationManager manager = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (manager != null) manager.notify(NOTIFICATION_ID, notification(text, 0, 0, false));
    }

    private Notification notification(String text, int completed, int total, boolean ongoing) {
        Intent open = new Intent(this, MainActivity.class);
        PendingIntent openIntent = PendingIntent.getActivity(this, 1, open,
                PendingIntent.FLAG_UPDATE_CURRENT | immutableFlag());
        Intent cancel = new Intent(this, ScanForegroundService.class).setAction(ACTION_CANCEL_SCAN);
        PendingIntent cancelIntent = PendingIntent.getService(this, 2, cancel,
                PendingIntent.FLAG_UPDATE_CURRENT | immutableFlag());
        Notification.Builder builder = Build.VERSION.SDK_INT >= 26
                ? new Notification.Builder(this, CHANNEL) : new Notification.Builder(this);
        builder.setSmallIcon(android.R.drawable.stat_notify_sync)
                .setContentTitle("IP系统情报 · 后台服务")
                .setContentText(text)
                .setContentIntent(openIntent)
                .setOngoing(ongoing)
                .setOnlyAlertOnce(true)
                .setColor(Color.rgb(55, 107, 255));
        if (total > 0) builder.setProgress(total, Math.min(completed, total), false);
        if (ongoing) builder.addAction(android.R.drawable.ic_menu_close_clear_cancel, "取消", cancelIntent);
        else builder.setAutoCancel(true);
        return builder.build();
    }

    private void createChannel() {
        if (Build.VERSION.SDK_INT < 26) return;
        NotificationManager manager = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (manager == null) return;
        NotificationChannel channel = new NotificationChannel(CHANNEL, "后台检测任务",
                NotificationManager.IMPORTANCE_LOW);
        channel.setDescription("显示批量 IP、订阅和 AI 可用性检测的后台进度");
        manager.createNotificationChannel(channel);
    }

    private Map<String, String> parseOrigins(String text) {
        Map<String, String> out = new LinkedHashMap<>();
        if (text == null || text.trim().isEmpty()) return out;
        try {
            JSONObject root = new JSONObject(text);
            java.util.Iterator<String> keys = root.keys();
            while (keys.hasNext()) {
                String key = keys.next();
                out.put(key, root.optString(key));
            }
        } catch (Exception ignored) { }
        return out;
    }

    private int immutableFlag() { return Build.VERSION.SDK_INT >= 23 ? PendingIntent.FLAG_IMMUTABLE : 0; }
    private String clean(String value, String fallback) {
        return value == null || value.trim().isEmpty() ? fallback : value.trim();
    }

    private List<String> limit(List<String> values, int count) {
        List<String> out = new ArrayList<>();
        for (int i = 0; i < values.size() && i < count; i++) out.add(values.get(i));
        if (values.size() > count) out.add("另有 " + (values.size() - count) + " 条"); return out;
    }

    private String safe(Exception e) {
        String message = e.getMessage();
        if (message == null || message.trim().isEmpty()) return e.getClass().getSimpleName();
        return message.replaceAll("token=[^&\\s]+", "token=***").replaceAll("key=[^&\\s]+", "key=***");
    }
}
