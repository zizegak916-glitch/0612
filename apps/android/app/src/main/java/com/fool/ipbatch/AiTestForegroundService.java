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

public final class AiTestForegroundService extends Service {
    public static final String ACTION_START = "com.fool.ipbatch.START_AI_TEST";
    public static final String ACTION_STATE = "com.fool.ipbatch.AI_TEST_STATE";
    public static final String EXTRA_CHECK = "check";
    public static final String EXTRA_COMPLETED = "completed";
    public static final String EXTRA_TOTAL = "total";
    public static final String EXTRA_RUNNING = "running";

    private static final String CHANNEL = "ai_reachability";
    private static final int NOTIFICATION_ID = 7312;
    private volatile boolean running;

    @Override public void onCreate() { super.onCreate(); createChannel(); }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_START.equals(intent.getAction()) && !running) {
            running = true; promote("正在检测 AI 平台入口…", 0, AiReachabilityTester.endpointCount(), true);
            final AiReachabilityTester.Report initial = new AiReachabilityTester.Report();
            initial.startedAt = System.currentTimeMillis(); AiReportStore.save(this, initial, true);
            new Thread(new Runnable() { @Override public void run() {
                final AiReachabilityTester.Report report = new AiReachabilityTester().testAll(10000,
                        new AiReachabilityTester.Listener() { @Override public void onCheck(
                                AiReachabilityTester.Check check, int completed, int total) {
                            initial.checks.add(check); AiReportStore.save(AiTestForegroundService.this, initial, true);
                            broadcast(check, completed, total, true);
                            notifyProgress("AI 平台入口检测 " + completed + "/" + total, completed, total, true);
                        }});
                AiReportStore.save(AiTestForegroundService.this, report, false);
                running = false; broadcast(null, report.checks.size(), report.checks.size(), false);
                if (Build.VERSION.SDK_INT >= 24) stopForeground(STOP_FOREGROUND_DETACH); else stopForeground(false);
                notifyProgress(report.summary(), 0, 0, false); stopSelf();
            }}, "ai-reachability").start();
        }
        return START_NOT_STICKY;
    }

    @Override public IBinder onBind(Intent intent) { return null; }

    private void broadcast(AiReachabilityTester.Check check, int completed, int total, boolean active) {
        Intent state = new Intent(ACTION_STATE).setPackage(getPackageName());
        state.putExtra(EXTRA_COMPLETED, completed); state.putExtra(EXTRA_TOTAL, total); state.putExtra(EXTRA_RUNNING, active);
        if (check != null) try { state.putExtra(EXTRA_CHECK, AiReportStore.encode(check).toString()); }
        catch (Exception ignored) { }
        sendBroadcast(state);
    }

    private void promote(String text, int completed, int total, boolean ongoing) {
        Notification value = notification(text, completed, total, ongoing);
        if (Build.VERSION.SDK_INT >= 29) startForeground(NOTIFICATION_ID, value, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC);
        else startForeground(NOTIFICATION_ID, value);
    }

    private void notifyProgress(String text, int completed, int total, boolean ongoing) {
        NotificationManager manager = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (manager != null) manager.notify(NOTIFICATION_ID, notification(text, completed, total, ongoing));
    }

    private Notification notification(String text, int completed, int total, boolean ongoing) {
        PendingIntent open = PendingIntent.getActivity(this, 3, new Intent(this, MainActivity.class),
                PendingIntent.FLAG_UPDATE_CURRENT | (Build.VERSION.SDK_INT >= 23 ? PendingIntent.FLAG_IMMUTABLE : 0));
        Notification.Builder builder = Build.VERSION.SDK_INT >= 26
                ? new Notification.Builder(this, CHANNEL) : new Notification.Builder(this);
        builder.setSmallIcon(android.R.drawable.stat_sys_download_done).setContentTitle("AI 平台系统路由直测")
                .setContentText(text).setContentIntent(open).setOngoing(ongoing).setOnlyAlertOnce(true)
                .setColor(Color.rgb(55, 107, 255));
        if (total > 0) builder.setProgress(total, completed, false); else builder.setAutoCancel(true);
        return builder.build();
    }

    private void createChannel() {
        if (Build.VERSION.SDK_INT < 26) return;
        NotificationManager manager = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (manager == null) return;
        NotificationChannel channel = new NotificationChannel(CHANNEL, "AI 平台直测", NotificationManager.IMPORTANCE_LOW);
        channel.setDescription("显示当前设备系统路由访问 AI 平台公开入口的检测进度");
        manager.createNotificationChannel(channel);
    }
}
