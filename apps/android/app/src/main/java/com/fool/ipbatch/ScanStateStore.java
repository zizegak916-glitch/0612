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
import java.util.List;

public final class ScanStateStore {
    private static final String FILE_NAME = "last_scan_state.json";

    public static final class Snapshot {
        public String label = "手动输入";
        public boolean running;
        public boolean cancelled;
        public int total;
        public int completed;
        public long startedAt;
        public long updatedAt;
        public final List<IpResult> results = new ArrayList<>();
    }

    private ScanStateStore() {}

    public static synchronized void save(Context context, Snapshot snapshot) {
        File target = new File(context.getFilesDir(), FILE_NAME);
        File temp = new File(context.getFilesDir(), FILE_NAME + ".tmp");
        try {
            JSONObject root = encode(snapshot);
            FileOutputStream output = new FileOutputStream(temp, false);
            output.write(root.toString().getBytes(StandardCharsets.UTF_8));
            output.flush();
            output.close();
            if (!temp.renameTo(target)) {
                FileOutputStream fallback = new FileOutputStream(target, false);
                fallback.write(root.toString().getBytes(StandardCharsets.UTF_8));
                fallback.close();
                temp.delete();
            }
        } catch (Exception ignored) { }
    }

    public static synchronized Snapshot load(Context context) {
        File target = new File(context.getFilesDir(), FILE_NAME);
        if (!target.isFile()) return null;
        try {
            BufferedReader reader = null;
            StringBuilder text = new StringBuilder();
            try {
                reader = new BufferedReader(new InputStreamReader(new FileInputStream(target), StandardCharsets.UTF_8));
                String line;
                while ((line = reader.readLine()) != null) {
                    text.append(line);
                    if (text.length() > 12 * 1024 * 1024) throw new Exception("状态文件过大");
                }
            } finally {
                if (reader != null) reader.close();
            }
            return decode(new JSONObject(text.toString()));
        } catch (Exception ignored) {
            return null;
        }
    }

    private static JSONObject encode(Snapshot snapshot) throws Exception {
        JSONObject root = new JSONObject();
        root.put("label", snapshot.label);
        root.put("running", snapshot.running);
        root.put("cancelled", snapshot.cancelled);
        root.put("total", snapshot.total);
        root.put("completed", snapshot.completed);
        root.put("started_at", snapshot.startedAt);
        root.put("updated_at", System.currentTimeMillis());
        JSONArray results = new JSONArray();
        for (IpResult result : snapshot.results) results.put(encodeResult(result));
        root.put("results", results);
        return root;
    }

    private static Snapshot decode(JSONObject root) throws Exception {
        Snapshot snapshot = new Snapshot();
        snapshot.label = root.optString("label", "手动输入");
        snapshot.running = root.optBoolean("running");
        snapshot.cancelled = root.optBoolean("cancelled");
        snapshot.total = root.optInt("total");
        snapshot.completed = root.optInt("completed");
        snapshot.startedAt = root.optLong("started_at");
        snapshot.updatedAt = root.optLong("updated_at");
        JSONArray results = root.optJSONArray("results");
        if (results != null) for (int i = 0; i < results.length(); i++) {
            JSONObject value = results.optJSONObject(i);
            if (value != null) snapshot.results.add(decodeResult(value));
        }
        if (snapshot.running && System.currentTimeMillis() - snapshot.updatedAt > 6L * 60L * 60L * 1000L) {
            snapshot.running = false;
            for (IpResult result : snapshot.results) if ("等待".equals(result.status) || "检测中".equals(result.status)) {
                result.status = "任务中断";
            }
        }
        return snapshot;
    }

    public static JSONObject encodeResult(IpResult value) throws Exception {
        JSONObject out = new JSONObject();
        out.put("ip", value.ip); out.put("origin", value.origin); out.put("status", value.status);
        if (value.riskScore != null) out.put("risk_score", value.riskScore);
        out.put("risk_source", value.riskSource); out.put("country", value.country); out.put("country_code", value.countryCode); out.put("region", value.region);
        out.put("city", value.city); out.put("asn", value.asn); out.put("org", value.org);
        out.put("network_type", value.networkType); out.put("coordinates", value.coordinates);
        out.put("timezone", value.timezone); out.put("registration", value.registration);
        out.put("routing", value.routing); out.put("freshness", value.freshness);
        out.put("confidence", value.confidence); out.put("conflicts", array(value.conflicts));
        out.put("signal_summary", value.signalSummary); out.put("signal_evidence", array(value.signalEvidence));
        out.put("vpn", value.vpn); out.put("proxy", value.proxy); out.put("tor", value.tor);
        out.put("datacenter", value.datacenter); out.put("abuser", value.abuser); out.put("mobile", value.mobile);
        out.put("risk_evaluated", value.riskEvaluated);
        if (value.nativeIp != null) out.put("native_ip", value.nativeIp);
        out.put("successful_sources", value.successfulSources); out.put("started_at", value.startedAt);
        out.put("country_agreement", value.countryAgreement); out.put("asn_agreement", value.asnAgreement);
        out.put("finished_at", value.finishedAt); out.put("source_details", array(value.sourceDetails));
        out.put("source_evidence", array(value.sourceEvidence)); out.put("errors", array(value.errors));
        return out;
    }

    public static IpResult decodeResult(JSONObject value) {
        IpResult out = new IpResult(value.optString("ip"));
        out.origin = value.optString("origin"); out.status = value.optString("status", "等待");
        if (value.has("risk_score")) out.riskScore = value.optInt("risk_score");
        out.riskSource = value.optString("risk_source"); out.country = value.optString("country"); out.countryCode = value.optString("country_code");
        out.region = value.optString("region"); out.city = value.optString("city"); out.asn = value.optString("asn");
        out.org = value.optString("org"); out.networkType = value.optString("network_type");
        out.coordinates = value.optString("coordinates"); out.timezone = value.optString("timezone");
        out.registration = value.optString("registration"); out.routing = value.optString("routing");
        out.freshness = value.optString("freshness"); out.confidence = value.optString("confidence", "未知");
        add(out.conflicts, value.optJSONArray("conflicts")); out.vpn = value.optBoolean("vpn");
        out.signalSummary = value.optString("signal_summary", "风险信号未知"); add(out.signalEvidence, value.optJSONArray("signal_evidence"));
        out.proxy = value.optBoolean("proxy"); out.tor = value.optBoolean("tor");
        out.datacenter = value.optBoolean("datacenter"); out.abuser = value.optBoolean("abuser");
        out.mobile = value.optBoolean("mobile"); out.riskEvaluated = value.optBoolean("risk_evaluated");
        if (value.has("native_ip")) out.nativeIp = value.optBoolean("native_ip");
        out.successfulSources = value.optInt("successful_sources"); out.startedAt = value.optLong("started_at");
        out.countryAgreement = value.optInt("country_agreement"); out.asnAgreement = value.optInt("asn_agreement");
        out.finishedAt = value.optLong("finished_at");
        add(out.sourceDetails, value.optJSONArray("source_details"));
        add(out.sourceEvidence, value.optJSONArray("source_evidence")); add(out.errors, value.optJSONArray("errors"));
        return out;
    }

    private static JSONArray array(List<String> values) {
        JSONArray out = new JSONArray();
        for (String value : values) out.put(value);
        return out;
    }

    private static void add(List<String> target, JSONArray values) {
        if (values == null) return;
        for (int i = 0; i < values.length(); i++) target.add(values.optString(i));
    }
}
