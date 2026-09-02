package com.fool.ipbatch;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class ScanHistoryStore {
    private static final String FILE_NAME = "scan_history.json";
    private static final int MAX_HISTORY = 10;

    public static final class Entry {
        public String label = "";
        public long time;
        public int total, high, warning, info, low, failed;
        public final Map<String, Item> items = new LinkedHashMap<>();
    }

    public static final class Item {
        public String ip = "", status = "", countryCode = "", asn = "";
        public Integer risk;
        public boolean vpn, proxy, tor, datacenter;
    }

    private ScanHistoryStore() {}

    public static synchronized void archive(Context context, ScanStateStore.Snapshot snapshot) {
        if (snapshot == null || snapshot.results.isEmpty()) return;
        try {
            JSONArray history = readArray(context);
            JSONArray next = new JSONArray(); next.put(encode(snapshot));
            for (int i = 0; i < history.length() && next.length() < MAX_HISTORY; i++) next.put(history.opt(i));
            write(context, next);
        } catch (Exception ignored) { }
    }

    public static synchronized List<Entry> list(Context context) {
        List<Entry> out = new ArrayList<>();
        try {
            JSONArray values = readArray(context);
            for (int i = 0; i < values.length(); i++) {
                JSONObject value = values.optJSONObject(i); if (value != null) out.add(decode(value));
            }
        } catch (Exception ignored) { }
        return out;
    }

    public static String compare(Entry newest, Entry older) {
        if (newest == null || older == null) return "至少需要两次扫描才能比较";
        int added = 0, removed = 0, statusChanged = 0, riskChanged = 0;
        for (Item item : newest.items.values()) {
            Item old = older.items.get(item.ip);
            if (old == null) { added++; continue; }
            if (!item.status.equals(old.status)) statusChanged++;
            if (item.risk != null && old.risk != null && Math.abs(item.risk - old.risk) >= 15) riskChanged++;
        }
        for (String ip : older.items.keySet()) if (!newest.items.containsKey(ip)) removed++;
        return "与上一次相比：新增 IP " + added + " · 消失 IP " + removed + " · 状态变化 " + statusChanged
                + " · 风险分变化≥15 " + riskChanged;
    }

    private static JSONObject encode(ScanStateStore.Snapshot snapshot) throws Exception {
        JSONObject out = new JSONObject(); out.put("label", snapshot.label);
        out.put("time", System.currentTimeMillis()); out.put("total", snapshot.total);
        JSONArray items = new JSONArray();
        for (IpResult result : snapshot.results) {
            JSONObject item = new JSONObject(); item.put("ip", result.ip); item.put("status", result.status);
            item.put("country_code", result.countryCode); item.put("asn", result.asn);
            if (result.riskScore != null) item.put("risk", result.riskScore);
            item.put("vpn", result.vpn); item.put("proxy", result.proxy); item.put("tor", result.tor);
            item.put("datacenter", result.datacenter); items.put(item);
            if ("高风险".equals(result.status)) out.put("high", out.optInt("high") + 1);
            else if ("需注意".equals(result.status)) out.put("warning", out.optInt("warning") + 1);
            else if ("信息可用".equals(result.status)) out.put("info", out.optInt("info") + 1);
            else if ("低风险".equals(result.status)) out.put("low", out.optInt("low") + 1);
            else if ("失败".equals(result.status)) out.put("failed", out.optInt("failed") + 1);
        }
        out.put("items", items); return out;
    }

    private static Entry decode(JSONObject value) {
        Entry out = new Entry(); out.label = value.optString("label"); out.time = value.optLong("time");
        out.total = value.optInt("total"); out.high = value.optInt("high"); out.warning = value.optInt("warning");
        out.info = value.optInt("info"); out.low = value.optInt("low"); out.failed = value.optInt("failed");
        JSONArray items = value.optJSONArray("items");
        if (items != null) for (int i = 0; i < items.length(); i++) {
            JSONObject valueItem = items.optJSONObject(i); if (valueItem == null) continue;
            Item item = new Item(); item.ip = valueItem.optString("ip"); item.status = valueItem.optString("status");
            item.countryCode = valueItem.optString("country_code"); item.asn = valueItem.optString("asn");
            if (valueItem.has("risk")) item.risk = valueItem.optInt("risk"); item.vpn = valueItem.optBoolean("vpn");
            item.proxy = valueItem.optBoolean("proxy"); item.tor = valueItem.optBoolean("tor");
            item.datacenter = valueItem.optBoolean("datacenter"); if (!item.ip.isEmpty()) out.items.put(item.ip, item);
        }
        return out;
    }

    private static JSONArray readArray(Context context) throws Exception {
        File file = new File(context.getFilesDir(), FILE_NAME); if (!file.isFile()) return new JSONArray();
        BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8));
        StringBuilder text = new StringBuilder();
        try { String line; while ((line = reader.readLine()) != null) text.append(line); }
        finally { reader.close(); }
        return text.length() == 0 ? new JSONArray() : new JSONArray(text.toString());
    }

    private static void write(Context context, JSONArray values) throws Exception {
        FileOutputStream output = context.openFileOutput(FILE_NAME, Context.MODE_PRIVATE);
        try { output.write(values.toString().getBytes(StandardCharsets.UTF_8)); }
        finally { output.close(); }
    }
}
