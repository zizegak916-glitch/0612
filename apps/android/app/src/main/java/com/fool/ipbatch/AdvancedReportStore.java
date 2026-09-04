package com.fool.ipbatch;

import android.content.Context;
import android.content.SharedPreferences;

/** Persists the latest rendered report only; subscription URLs, contents and controller secrets are excluded. */
public final class AdvancedReportStore {
    private static final String PREFS = "advanced_report_v1";
    private AdvancedReportStore() { }
    public static void save(Context context, String kind, String report, String error, boolean running) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
                .putString("kind", kind == null ? "" : kind)
                .putString("report", clip(report, 600000))
                .putString("error", clip(error, 1000))
                .putBoolean("running", running)
                .putLong("updated", System.currentTimeMillis()).apply();
    }
    public static State load(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        State state = new State(); state.kind = prefs.getString("kind", ""); state.report = prefs.getString("report", "");
        state.error = prefs.getString("error", ""); state.running = prefs.getBoolean("running", false); state.updated = prefs.getLong("updated", 0); return state;
    }
    private static String clip(String value, int max) { if (value == null) return ""; return value.length() <= max ? value : value.substring(0, max) + "\n[报告已截断]"; }
    public static final class State { public String kind, report, error; public boolean running; public long updated; }
}
