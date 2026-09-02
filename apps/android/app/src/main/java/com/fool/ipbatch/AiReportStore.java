package com.fool.ipbatch;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

public final class AiReportStore {
    private static final String PREFS = "ai_test_state";
    private static final String KEY = "report";

    private AiReportStore() {}

    public static void save(Context context, AiReachabilityTester.Report report, boolean running) {
        try {
            JSONObject root = new JSONObject();
            root.put("running", running); root.put("started_at", report.startedAt);
            root.put("finished_at", report.finishedAt); root.put("updated_at", System.currentTimeMillis());
            JSONArray checks = new JSONArray();
            synchronized (report.checks) {
                for (AiReachabilityTester.Check check : report.checks) checks.put(encode(check));
            }
            root.put("checks", checks);
            context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putString(KEY, root.toString()).apply();
        } catch (Exception ignored) { }
    }

    public static State load(Context context) {
        String text = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(KEY, "");
        if (text.isEmpty()) return null;
        try {
            JSONObject root = new JSONObject(text); State state = new State();
            state.running = root.optBoolean("running"); state.report.startedAt = root.optLong("started_at");
            state.report.finishedAt = root.optLong("finished_at"); state.updatedAt = root.optLong("updated_at");
            JSONArray checks = root.optJSONArray("checks");
            if (checks != null) for (int i = 0; i < checks.length(); i++) {
                JSONObject item = checks.optJSONObject(i); if (item != null) state.report.checks.add(decode(item));
            }
            if (state.running && System.currentTimeMillis() - state.updatedAt > 10L * 60L * 1000L) state.running = false;
            return state;
        } catch (Exception ignored) { return null; }
    }

    public static JSONObject encode(AiReachabilityTester.Check value) throws Exception {
        JSONObject out = new JSONObject();
        out.put("platform", value.platform); out.put("surface", value.surface); out.put("host", value.host);
        out.put("status", value.status); out.put("detail", value.detail); out.put("http_code", value.httpCode);
        out.put("duration_ms", value.durationMs); out.put("checked_at", value.checkedAt); return out;
    }

    public static AiReachabilityTester.Check decode(JSONObject value) {
        AiReachabilityTester.Check out = new AiReachabilityTester.Check();
        out.platform = value.optString("platform"); out.surface = value.optString("surface");
        out.host = value.optString("host"); out.status = value.optString("status"); out.detail = value.optString("detail");
        out.httpCode = value.optInt("http_code"); out.durationMs = value.optLong("duration_ms");
        out.checkedAt = value.optLong("checked_at"); return out;
    }

    public static final class State {
        public boolean running;
        public long updatedAt;
        public final AiReachabilityTester.Report report = new AiReachabilityTester.Report();
    }
}
