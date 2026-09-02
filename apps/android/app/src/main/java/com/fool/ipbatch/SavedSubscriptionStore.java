package com.fool.ipbatch;

import org.json.JSONArray;
import org.json.JSONObject;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public final class SavedSubscriptionStore {
    private static final String KEY = "subscriptions_json";
    private static final int MAX_ITEMS = 20;
    private final SecretStore secrets;

    public static final class Entry {
        public String url = "";
        public String label = "";
        public long savedAt;
    }

    public SavedSubscriptionStore(SecretStore secrets) { this.secrets = secrets; }

    public List<Entry> list() {
        List<Entry> out = new ArrayList<>();
        String text = secrets.get(KEY);
        if (text.isEmpty()) return out;
        try {
            JSONArray values = new JSONArray(text);
            for (int i = 0; i < values.length(); i++) {
                JSONObject value = values.optJSONObject(i); if (value == null) continue;
                Entry entry = new Entry(); entry.url = value.optString("url");
                entry.label = value.optString("label"); entry.savedAt = value.optLong("saved_at");
                if (!entry.url.isEmpty()) out.add(entry);
            }
        } catch (Exception ignored) { }
        return out;
    }

    public void save(String url) throws Exception {
        String clean = url == null ? "" : url.trim();
        if (clean.isEmpty()) return;
        List<Entry> values = list();
        Entry selected = null;
        for (Entry value : values) if (value.url.equals(clean)) { selected = value; break; }
        if (selected == null) { selected = new Entry(); values.add(0, selected); }
        selected.url = clean; selected.label = displayLabel(clean); selected.savedAt = System.currentTimeMillis();
        while (values.size() > MAX_ITEMS) values.remove(values.size() - 1);
        write(values);
    }

    public void remove(String url) throws Exception {
        List<Entry> values = list();
        for (int i = values.size() - 1; i >= 0; i--) if (values.get(i).url.equals(url)) values.remove(i);
        write(values);
    }

    public String firstUrl() {
        List<Entry> values = list(); return values.isEmpty() ? "" : values.get(0).url;
    }

    private void write(List<Entry> values) throws Exception {
        JSONArray out = new JSONArray();
        for (Entry entry : values) {
            JSONObject value = new JSONObject(); value.put("url", entry.url);
            value.put("label", entry.label); value.put("saved_at", entry.savedAt); out.put(value);
        }
        if (values.isEmpty()) secrets.remove(KEY); else secrets.put(KEY, out.toString());
    }

    private String displayLabel(String address) {
        try {
            URL url = new URL(address);
            return url.getHost() + " · " + url.getProtocol().toUpperCase();
        } catch (Exception ignored) { return "已保存订阅"; }
    }
}
