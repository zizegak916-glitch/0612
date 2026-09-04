package com.fool.ipbatch;

import android.content.Context;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

/** Success-only result cache. It never stores subscription URLs, node secrets, or API keys. */
public final class IpEvidenceCache {
    private static final long TTL_MS = 15L * 60L * 1000L;
    private static final String FILE = "provider_result_cache_v1.json";
    private final File target;
    private JSONObject entries;

    public IpEvidenceCache(Context context) {
        target = new File(context.getFilesDir(), FILE);
        entries = read();
    }

    public synchronized IpResult get(String ip, ApiClient.Settings settings) {
        if (!settings.useCache) return null;
        JSONObject item = entries.optJSONObject(key(ip, settings));
        if (item == null) return null;
        long age = System.currentTimeMillis() - item.optLong("stored_at");
        if (age < 0 || age > TTL_MS) return null;
        JSONObject value = item.optJSONObject("result");
        if (value == null) return null;
        IpResult result = ScanStateStore.decodeResult(value);
        result.startedAt = System.currentTimeMillis();
        result.finishedAt = result.startedAt;
        result.sourceEvidence.add(0, "本地缓存：命中 · 年龄 " + Math.max(0, age / 1000L) + " 秒 · TTL 900 秒");
        result.confidence = result.confidence + " · 缓存 " + Math.max(0, age / 1000L) + " 秒";
        return result;
    }

    public synchronized void put(IpResult result, ApiClient.Settings settings) {
        if (!settings.useCache || result.successfulSources == 0 || "失败".equals(result.status)
                || "私网/保留".equals(result.status) || "已取消".equals(result.status)) return;
        try {
            JSONObject item = new JSONObject();
            item.put("stored_at", System.currentTimeMillis());
            item.put("result", ScanStateStore.encodeResult(result));
            entries.put(key(result.ip, settings), item);
            write();
        } catch (Exception ignored) { }
    }

    private String key(String ip, ApiClient.Settings s) {
        return ip + "|" + bit(s.ipapi) + bit(s.proxyCheck) + bit(s.geoJs) + bit(s.rdap)
                + bit(s.ripeStat) + bit(s.ping0) + bit(!s.ipapiKey.isEmpty())
                + bit(!s.proxyCheckKey.isEmpty()) + bit(!s.ping0Key.isEmpty());
    }

    private String bit(boolean value) { return value ? "1" : "0"; }

    private JSONObject read() {
        if (!target.isFile()) return new JSONObject();
        try {
            StringBuilder text = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(target), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    text.append(line);
                    if (text.length() > 16 * 1024 * 1024) throw new Exception("cache too large");
                }
            }
            return new JSONObject(text.toString());
        } catch (Exception ignored) { return new JSONObject(); }
    }

    private void write() {
        File temporary = new File(target.getParentFile(), FILE + ".tmp");
        try {
            FileOutputStream output = new FileOutputStream(temporary, false);
            output.write(entries.toString().getBytes(StandardCharsets.UTF_8));
            output.flush(); output.close();
            if (!temporary.renameTo(target)) {
                FileOutputStream fallback = new FileOutputStream(target, false);
                fallback.write(entries.toString().getBytes(StandardCharsets.UTF_8));
                fallback.close(); temporary.delete();
            }
        } catch (Exception ignored) { }
    }
}
