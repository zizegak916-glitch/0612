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

public final class AdvancedTestForegroundService extends Service {
    public static final String ACTION_DETAIL = "com.fool.ipbatch.ADVANCED_DETAIL";
    public static final String ACTION_STATE = "com.fool.ipbatch.ADVANCED_STATE";
    public static final String EXTRA_IP = "ip";
    private static final String CHANNEL = "advanced-tests";
    private static final int NOTIFICATION_ID = 9303;
    private volatile boolean running;

    @Override public void onCreate() { super.onCreate(); createChannel(); }
    @Override public int onStartCommand(final Intent intent, int flags, int startId) {
        if (intent == null || running) return START_NOT_STICKY;
        final String action = intent.getAction();
        if (!ACTION_DETAIL.equals(action)) return START_NOT_STICKY;
        running = true; promote("正在调查单个 IP…", true);
        final String kind = "detail";
        AdvancedReportStore.save(this, kind, "", "", true); broadcast();
        new Thread(new Runnable() { @Override public void run() {
            String report = "", error = "";
            try {
                report = new DetailedIpInvestigator().investigate(
                        intent.getStringExtra(EXTRA_IP), SettingsRepository.load(AdvancedTestForegroundService.this));
            } catch (Exception failure) { error = safe(failure); }
            running = false; AdvancedReportStore.save(AdvancedTestForegroundService.this, kind, report, error, false); broadcast();
            if (Build.VERSION.SDK_INT >= 24) stopForeground(STOP_FOREGROUND_DETACH); else stopForeground(false);
            promote(error.isEmpty() ? "任务完成，点击查看报告" : "任务失败：" + error, false); stopSelf();
        }}, "advanced-network-test").start();
        return START_NOT_STICKY;
    }
    @Override public IBinder onBind(Intent intent) { return null; }
    private void broadcast() { sendBroadcast(new Intent(ACTION_STATE).setPackage(getPackageName())); }
    private void promote(String text, boolean ongoing) {
        PendingIntent open = PendingIntent.getActivity(this, 30, new Intent(this, MainActivity.class), PendingIntent.FLAG_UPDATE_CURRENT | (Build.VERSION.SDK_INT >= 23 ? PendingIntent.FLAG_IMMUTABLE : 0));
        Notification.Builder builder = Build.VERSION.SDK_INT >= 26 ? new Notification.Builder(this, CHANNEL) : new Notification.Builder(this);
        Notification value = builder.setSmallIcon(android.R.drawable.stat_notify_sync).setContentTitle("IP系统情报 · 高级模式")
                .setContentText(text).setContentIntent(open).setOnlyAlertOnce(true).setOngoing(ongoing).setColor(Color.rgb(55, 107, 255)).build();
        if (ongoing) { if (Build.VERSION.SDK_INT >= 29) startForeground(NOTIFICATION_ID, value, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC); else startForeground(NOTIFICATION_ID, value); }
        else { NotificationManager manager = (NotificationManager) getSystemService(NOTIFICATION_SERVICE); if (manager != null) manager.notify(NOTIFICATION_ID, value); }
    }
    private void createChannel() { if (Build.VERSION.SDK_INT < 26) return; NotificationManager manager = (NotificationManager) getSystemService(NOTIFICATION_SERVICE); if (manager != null) manager.createNotificationChannel(new NotificationChannel(CHANNEL, "单 IP 详细调查", NotificationManager.IMPORTANCE_LOW)); }
    private String safe(Exception error) { String value = error.getMessage(); if (value == null || value.trim().isEmpty()) value = error.getClass().getSimpleName(); value = value.replace('\n', ' ').replace('\r', ' '); return value.length() <= 900 ? value : value.substring(0, 900); }
}
