package com.fool.ipbatch;

import android.app.Application;
import android.util.Log;

import java.io.File;
import java.util.Locale;

import io.nekohasekai.libbox.Libbox;
import io.nekohasekai.libbox.SetupOptions;

public final class InspectorApplication extends Application {
    private static volatile String setupError = "";

    @Override public void onCreate() {
        super.onCreate();
        try {
            File base = getFilesDir(); File work = getExternalFilesDir(null); File temp = getCacheDir();
            if (work == null) work = base;
            SetupOptions options = new SetupOptions();
            options.setBasePath(base.getAbsolutePath()); options.setWorkingPath(work.getAbsolutePath());
            options.setTempPath(temp.getAbsolutePath()); options.setFixAndroidStack(true);
            options.setLogMaxLines(1200); options.setDebug(false); options.setCrashReportSource("IPBatchInspector");
            options.setAppVersion("8"); options.setAppMarketingVersion("6.0.0-alpha.1");
            Libbox.setup(options); Libbox.setLocale(Locale.getDefault().toLanguageTag());
        } catch (Throwable failure) {
            setupError = safe(failure); Log.e("IPBatchInspector", "libbox setup failed", failure);
        }
    }

    public static void requireLibbox() throws Exception {
        if (!setupError.isEmpty()) throw new Exception("libbox 初始化失败：" + setupError);
    }

    private static String safe(Throwable error) {
        String value = error.getMessage(); if (value == null || value.trim().isEmpty()) value = error.getClass().getSimpleName();
        return value.replace('\n', ' ').replace('\r', ' ');
    }
}
