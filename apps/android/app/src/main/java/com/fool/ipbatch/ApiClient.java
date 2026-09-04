package com.fool.ipbatch;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import java.util.Date;
import java.text.SimpleDateFormat;
import java.util.Locale;
import java.util.TimeZone;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.LinkedHashMap;
import java.util.Map;

public final class ApiClient {
    private static final ExecutorService PROVIDER_POOL = Executors.newFixedThreadPool(10);
    private static final Object RDAP_RATE_LOCK = new Object();
    private static long lastRdapStarted;
    public static final class Settings {
        public boolean ipapi = true;
        public boolean proxyCheck = true;
        public boolean geoJs = true;
        public boolean rdap = true;
        public boolean ripeStat = true;
        public boolean ping0;
        public String ipapiKey = "";
        public String proxyCheckKey = "";
        public String ping0Key = "";
        public int timeoutMs = 12000;
        public boolean useCache = true;
    }

    public IpResult scan(String ip, Settings settings) {
        IpResult out = new IpResult(ip);
        out.startedAt = System.currentTimeMillis();
        out.status = "检测中";
        if (!IpParser.isPublic(ip)) {
            out.status = "私网/保留";
            out.sourceDetails.add("本机规则：未向外部服务发送");
            out.finishedAt = System.currentTimeMillis();
            return out;
        }
        List<Future<IpResult>> futures = new ArrayList<>();
        List<String> sourceOrder = new ArrayList<>();
        if (settings.ipapi) add(futures, sourceOrder, "ipapi.is", ip, new PartialRequest() {
            @Override public void run(IpResult partial) throws Exception { queryIpApi(ip, partial, settings); }
        });
        if (settings.proxyCheck) add(futures, sourceOrder, "proxycheck.io", ip, new PartialRequest() {
            @Override public void run(IpResult partial) throws Exception { queryProxyCheck(ip, partial, settings); }
        });
        if (settings.geoJs) add(futures, sourceOrder, "GeoJS", ip, new PartialRequest() {
            @Override public void run(IpResult partial) throws Exception { queryGeoJs(ip, partial, settings.timeoutMs); }
        });
        if (settings.rdap) add(futures, sourceOrder, "RDAP", ip, new PartialRequest() {
            @Override public void run(IpResult partial) throws Exception { queryRdap(ip, partial, settings.timeoutMs); }
        });
        if (settings.ripeStat) add(futures, sourceOrder, "RIPEstat", ip, new PartialRequest() {
            @Override public void run(IpResult partial) throws Exception { queryRipeStat(ip, partial, settings.timeoutMs); }
        });
        if (settings.ping0 && !settings.ping0Key.trim().isEmpty()) add(futures, sourceOrder, "Ping0", ip, new PartialRequest() {
            @Override public void run(IpResult partial) throws Exception { queryPing0(ip, partial, settings); }
        });
        List<IpResult> partials = new ArrayList<>();
        for (int index = 0; index < futures.size(); index++) {
            try {
                IpResult partial = futures.get(index).get();
                partials.add(partial);
                out.mergeFrom(partial, sourceOrder.get(index));
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                out.errors.add(sourceOrder.get(index) + "：任务已中断");
            } catch (Exception failure) {
                out.errors.add(sourceOrder.get(index) + "：" + safeMessage(failure));
            }
        }
        applyConsensus(out, partials);
        out.finish();
        return out;
    }

    private interface Request { void run() throws Exception; }
    private interface PartialRequest { void run(IpResult partial) throws Exception; }

    private void add(List<Future<IpResult>> futures, List<String> sources, final String source,
                     final String ip, final PartialRequest request) {
        sources.add(source);
        futures.add(PROVIDER_POOL.submit(new Callable<IpResult>() {
            @Override public IpResult call() {
                final IpResult partial = new IpResult(ip);
                ApiClient.this.call(source, partial, new Request() {
                    @Override public void run() throws Exception { request.run(partial); }
                });
                return partial;
            }
        }));
    }

    private void call(String source, IpResult out, Request request) {
        long begin = System.currentTimeMillis();
        try {
            request.run();
            out.successfulSources++;
            out.sourceEvidence.add(source + "：成功 · " + (System.currentTimeMillis() - begin)
                    + " ms · " + utcNow());
        } catch (Exception e) {
            String message = safeMessage(e);
            out.errors.add(source + "：" + message + "（" + (System.currentTimeMillis() - begin) + " ms）");
        }
    }

    private void queryIpApi(String ip, IpResult out, Settings settings) throws Exception {
        String endpoint = "https://api.ipapi.is/?q=" + enc(ip);
        if (!settings.ipapiKey.trim().isEmpty()) endpoint += "&key=" + enc(settings.ipapiKey.trim());
        String body = get(endpoint, settings.timeoutMs);
        JSONObject root = new JSONObject(body);
        if (root.optBoolean("error", false)) throw new Exception(root.optString("message", "上游拒绝查询"));
        assertTarget(ip, root.optString("ip", ""));
        JSONObject location = root.optJSONObject("location");
        JSONObject asn = root.optJSONObject("asn");
        JSONObject company = root.optJSONObject("company");
        if (location != null) {
            fill(out, location.optString("country"), location.optString("state"), location.optString("city"));
            setCountryCode(out, first(location.optString("country_code"), location.optString("countryCode")));
            setCoordinates(out, location.opt("latitude"), location.opt("longitude"));
            setIfEmpty(out, "timezone", location.optString("timezone"));
        } else {
            fill(out, root.optString("country"), root.optString("region"), root.optString("city"));
            setCountryCode(out, first(root.optString("country_code"), root.optString("countryCode")));
            setCoordinates(out, root.opt("latitude"), root.opt("longitude"));
            setIfEmpty(out, "timezone", root.optString("timezone"));
        }
        if (asn != null) {
            setIfEmpty(out, "asn", formatAsn(asn.opt("asn")));
            setIfEmpty(out, "org", first(asn.optString("org"), asn.optString("name")));
            setIfEmpty(out, "networkType", asn.optString("type"));
        }
        if (company != null) {
            setIfEmpty(out, "org", company.optString("name"));
            setIfEmpty(out, "networkType", company.optString("type"));
        }
        if (asn == null) parseFlatAsn(out, root.optString("asn"));
        if (company == null) setIfEmpty(out, "org", root.optString("company"));
        out.vpn |= root.optBoolean("is_vpn");
        out.proxy |= root.optBoolean("is_proxy");
        out.tor |= root.optBoolean("is_tor");
        out.datacenter |= root.optBoolean("is_datacenter");
        out.abuser |= root.optBoolean("is_abuser");
        out.mobile |= root.optBoolean("is_mobile");
        boolean hasSecurity = root.has("is_vpn") || root.has("is_proxy") || root.has("is_tor")
                || root.has("is_datacenter") || root.has("is_abuser");
        out.riskEvaluated |= hasSecurity;
        for (String flag : new String[]{"proxy", "vpn", "tor", "datacenter", "abuser"}) {
            String key = "is_" + flag;
            if (root.has(key)) out.signalEvidence.add("ipapi.is|" + flag + "=" + root.optBoolean(key));
        }
        out.sourceDetails.add(hasSecurity
                ? "ipapi.is：归属/类型/匿名与滥用标记"
                : "ipapi.is：免费层归属与 ASN（高级风险字段未返回）");
    }

    private void queryProxyCheck(String ip, IpResult out, Settings settings) throws Exception {
        StringBuilder url = new StringBuilder("https://proxycheck.io/v2/").append(enc(ip))
                .append("?vpn=1&asn=1&risk=1&seen=1");
        if (!settings.proxyCheckKey.trim().isEmpty()) url.append("&key=").append(enc(settings.proxyCheckKey.trim()));
        JSONObject root = new JSONObject(get(url.toString(), settings.timeoutMs));
        if (!"ok".equalsIgnoreCase(root.optString("status"))) {
            throw new Exception(first(root.optString("message"), "状态异常"));
        }
        JSONObject data = findTargetObject(root, ip);
        if (data == null) throw new Exception("返回中没有目标 IP");
        String proxy = data.optString("proxy");
        String type = data.optString("type");
        out.riskEvaluated = true;
        out.proxy |= yes(proxy);
        out.vpn |= type.toLowerCase().contains("vpn");
        out.tor |= type.toLowerCase().contains("tor");
        out.signalEvidence.add("proxycheck.io|proxy=" + yes(proxy));
        out.signalEvidence.add("proxycheck.io|vpn=" + type.toLowerCase().contains("vpn"));
        out.signalEvidence.add("proxycheck.io|tor=" + type.toLowerCase().contains("tor"));
        if (data.has("risk")) out.acceptRisk(toInt(data.opt("risk"), 0), "proxycheck.io");
        fill(out, data.optString("country"), data.optString("region"), data.optString("city"));
        setCountryCode(out, first(data.optString("isocode"), data.optString("country_code")));
        setIfEmpty(out, "asn", formatAsn(data.opt("asn")));
        setIfEmpty(out, "org", first(data.optString("organisation"), data.optString("provider")));
        setIfEmpty(out, "networkType", type);
        String lastSeen = first(data.optString("last_seen"), data.optString("last seen"));
        if (!lastSeen.isEmpty()) out.freshness = addFreshness(out.freshness, "proxycheck.io 最后观测 " + lastSeen);
        out.sourceDetails.add("proxycheck.io：风险 " + (data.has("risk") ? data.opt("risk") + "/100" : "未返回")
                + "；代理 " + first(proxy, "未知") + "；类型 " + first(type, "未知")
                + (lastSeen.isEmpty() ? "" : "；最后观测 " + lastSeen));
    }

    private void queryGeoJs(String ip, IpResult out, int timeout) throws Exception {
        JSONObject root = new JSONObject(get("https://get.geojs.io/v1/ip/geo/" + enc(ip) + ".json", timeout));
        assertTarget(ip, root.optString("ip", ""));
        fill(out, root.optString("country"), root.optString("region"), root.optString("city"));
        setCountryCode(out, root.optString("country_code"));
        setIfEmpty(out, "asn", formatAsn(root.opt("asn")));
        setIfEmpty(out, "org", first(root.optString("organization_name"), root.optString("organization")));
        setCoordinates(out, root.opt("latitude"), root.opt("longitude"));
        setIfEmpty(out, "timezone", root.optString("timezone"));
        out.sourceDetails.add("GeoJS：" + joinLocation(root.optString("country"), root.optString("region"), root.optString("city"))
                + "；" + formatAsn(root.opt("asn")) + "；" + first(root.optString("organization_name"), root.optString("organization")));
    }

    private void queryRdap(String ip, IpResult out, int timeout) throws Exception {
        throttleRdap();
        JSONObject root = new JSONObject(getRedirecting("https://rdap.org/ip/" + enc(ip), timeout, 4));
        String start = clean(root.optString("startAddress"));
        String end = clean(root.optString("endAddress"));
        String name = first(root.optString("name"), root.optString("handle"));
        String country = clean(root.optString("country"));
        String type = clean(root.optString("type"));
        String status = joinJson(root.optJSONArray("status"), "/");
        String events = rdapEvents(root.optJSONArray("events"));
        String entities = rdapEntities(root.optJSONArray("entities"));
        StringBuilder detail = new StringBuilder();
        append(detail, "网段", range(start, end));
        append(detail, "名称", name);
        append(detail, "国家", country);
        append(detail, "类型", type);
        append(detail, "状态", status);
        append(detail, "事件", events);
        append(detail, "实体", entities);
        out.registration = detail.length() == 0 ? "未返回可展示的注册字段" : detail.toString();
        out.sourceDetails.add("RDAP 注册：" + out.registration);
    }

    private void queryRipeStat(String ip, IpResult out, int timeout) throws Exception {
        JSONObject root = new JSONObject(get("https://stat.ripe.net/data/routing-status/data.json?resource=" + enc(ip), timeout));
        JSONObject data = root.optJSONObject("data");
        if (data == null) throw new Exception("返回缺少 data");
        JSONObject lastSeen = data.optJSONObject("last_seen");
        JSONObject firstSeen = data.optJSONObject("first_seen");
        String prefix = lastSeen == null ? "" : clean(lastSeen.optString("prefix"));
        String origin = lastSeen == null ? "" : clean(String.valueOf(lastSeen.opt("origin"))).replaceAll("[^0-9]", "");
        String lastTime = lastSeen == null ? "" : clean(lastSeen.optString("time"));
        String firstTime = firstSeen == null ? "" : clean(firstSeen.optString("time"));
        JSONObject visibility = data.optJSONObject("visibility");
        JSONObject familyVisibility = visibility == null ? null : visibility.optJSONObject(ip.contains(":") ? "v6" : "v4");
        String visibilityText = "";
        if (familyVisibility != null) visibilityText = familyVisibility.optInt("ris_peers_seeing", 0) + "/"
                + familyVisibility.optInt("total_ris_peers", 0) + " RIS peers";
        JSONArray less = data.optJSONArray("less_specifics");
        JSONArray more = data.optJSONArray("more_specifics");
        String holder = "";
        try {
            JSONObject overviewRoot = new JSONObject(get("https://stat.ripe.net/data/prefix-overview/data.json?resource=" + enc(ip), timeout));
            JSONObject overview = overviewRoot.optJSONObject("data");
            if (overview != null) {
                JSONArray asns = overview.optJSONArray("asns");
                if (origin.isEmpty() && asns != null && asns.length() > 0) origin = asnValue(asns.opt(0));
                if (asns != null && asns.length() > 0 && asns.optJSONObject(0) != null) holder = clean(asns.optJSONObject(0).optString("holder"));
                if (holder.isEmpty()) holder = clean(overview.optString("holder"));
            }
        } catch (Exception ignored) { }
        String rpki = "";
        if (!prefix.isEmpty() && !origin.isEmpty()) {
            try {
                JSONObject rpkiRoot = new JSONObject(get("https://stat.ripe.net/data/rpki-validation/data.json?resource=AS"
                        + enc(origin) + "&prefix=" + enc(prefix), timeout));
                JSONObject rpkiData = rpkiRoot.optJSONObject("data");
                if (rpkiData != null) rpki = clean(rpkiData.optString("status"));
            } catch (Exception ignored) { rpki = "查询失败"; }
        }
        StringBuilder detail = new StringBuilder();
        append(detail, "当前宣告", lastSeen != null ? "是" : "未观察到");
        append(detail, "前缀", prefix);
        append(detail, "Origin ASN", origin.isEmpty() ? "" : "AS" + origin);
        append(detail, "持有者", holder);
        append(detail, "RIS 可见性", visibilityText);
        append(detail, "首次观测", firstTime);
        append(detail, "最后观测", lastTime);
        append(detail, "更宽/更细前缀", (less == null ? 0 : less.length()) + "/" + (more == null ? 0 : more.length()));
        append(detail, "RPKI", rpki);
        out.routing = detail.toString();
        if (!origin.isEmpty()) setIfEmpty(out, "asn", "AS" + origin);
        if (!holder.isEmpty()) setIfEmpty(out, "org", holder);
        if (!lastTime.isEmpty()) out.freshness = addFreshness(out.freshness, "RIPE RIS 最后观测 " + lastTime);
        out.sourceDetails.add("RIPEstat 路由：" + out.routing);
    }

    private void queryPing0(String ip, IpResult out, Settings settings) throws Exception {
        String endpoint = "https://ping0.cc/apiloc/apikey(" + enc(settings.ping0Key.trim()) + ")/ip(" + enc(ip) + ")";
        JSONObject root = new JSONObject(get(endpoint, settings.timeoutMs));
        assertTarget(ip, root.optString("ip", ""));
        fill(out, root.optString("country"), root.optString("province"), root.optString("city"));
        setCountryCode(out, first(root.optString("country_code"), first(root.optString("countrycode"), root.optString("countryCode"))));
        setIfEmpty(out, "asn", root.optString("asn"));
        setIfEmpty(out, "org", first(root.optString("org"), root.optString("asnname")));
        setIfEmpty(out, "networkType", first(root.optString("orgtype"), root.optString("asntype")));
        out.datacenter |= root.optBoolean("isidc");
        if (root.has("isidc")) out.signalEvidence.add("Ping0|datacenter=" + root.optBoolean("isidc"));
        out.riskEvaluated = true;
        if (root.has("iprisk")) out.acceptRisk(toInt(root.opt("iprisk"), 0), "Ping0");
        if (root.has("isnative")) out.nativeIp = root.optBoolean("isnative");
        out.sourceDetails.add("Ping0：风险分/原生IP/机房（官方付费 API）");
    }

    private String get(String address, int timeout) throws Exception {
        HttpURLConnection connection = (HttpURLConnection) new URL(address).openConnection();
        try {
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(timeout);
            connection.setReadTimeout(timeout);
            connection.setInstanceFollowRedirects(false);
            connection.setUseCaches(false);
            connection.setRequestProperty("Accept", "application/json");
            connection.setRequestProperty("User-Agent", "IPBatchInspector/4.1 Android");
            int code = connection.getResponseCode();
            InputStream input = code >= 200 && code < 300 ? connection.getInputStream() : connection.getErrorStream();
            String body = read(input);
            if (code == 429) throw new Exception("已限流，请稍后重试或填写 API Key");
            if (code >= 300 && code < 400) throw new Exception("上游发生重定向，已按隐私规则拒绝");
            if (code < 200 || code >= 300) throw new Exception("HTTP " + code);
            if (body.trim().isEmpty()) throw new Exception("返回为空");
            return body;
        } finally {
            connection.disconnect();
        }
    }

    private String getRedirecting(String address, int timeout, int redirectsLeft) throws Exception {
        URL current = new URL(address);
        for (int hop = 0; hop <= redirectsLeft; hop++) {
            if (!"https".equalsIgnoreCase(current.getProtocol())) throw new Exception("拒绝非 HTTPS 跳转");
            HttpURLConnection connection = (HttpURLConnection) current.openConnection();
            try {
                connection.setRequestMethod("GET");
                connection.setConnectTimeout(timeout);
                connection.setReadTimeout(timeout);
                connection.setInstanceFollowRedirects(false);
                connection.setUseCaches(false);
                connection.setRequestProperty("Accept", "application/rdap+json, application/json");
                connection.setRequestProperty("User-Agent", "IPBatchInspector/4.1 Android");
                int code = connection.getResponseCode();
                if (code >= 300 && code < 400) {
                    String location = connection.getHeaderField("Location");
                    if (location == null || location.trim().isEmpty()) throw new Exception("跳转缺少地址");
                    current = new URL(current, location);
                    continue;
                }
                InputStream input = code >= 200 && code < 300 ? connection.getInputStream() : connection.getErrorStream();
                String body = read(input);
                if (code == 429) throw new Exception("已限流");
                if (code < 200 || code >= 300) throw new Exception("HTTP " + code);
                if (body.trim().isEmpty()) throw new Exception("返回为空");
                return body;
            } finally {
                connection.disconnect();
            }
        }
        throw new Exception("跳转次数超过限制");
    }

    private String read(InputStream input) throws Exception {
        if (input == null) return "";
        BufferedReader reader = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8));
        StringBuilder body = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            body.append(line).append('\n');
            if (body.length() > 1024 * 1024) throw new Exception("返回内容过大");
        }
        reader.close();
        return body.toString();
    }

    private JSONObject findTargetObject(JSONObject root, String target) {
        Iterator<String> keys = root.keys();
        while (keys.hasNext()) {
            String key = keys.next();
            if ("status".equals(key) || "node".equals(key) || "message".equals(key)) continue;
            if (sameIp(key, target)) return root.optJSONObject(key);
        }
        return null;
    }

    private void assertTarget(String expected, String actual) throws Exception {
        if (actual.isEmpty() || !sameIp(expected, actual)) throw new Exception("目标 IP 回显不一致");
    }

    private boolean sameIp(String one, String two) {
        try {
            byte[] a = InetAddress.getByName(one).getAddress();
            byte[] b = InetAddress.getByName(two).getAddress();
            if (a.length != b.length) return false;
            for (int i = 0; i < a.length; i++) if (a[i] != b[i]) return false;
            return true;
        } catch (Exception ignored) { return false; }
    }

    private void fill(IpResult out, String country, String region, String city) {
        if (out.country.isEmpty()) out.country = clean(country);
        if (out.region.isEmpty()) out.region = clean(region);
        if (out.city.isEmpty()) out.city = clean(city);
    }

    private void setCountryCode(IpResult out, String value) {
        String code = clean(value).toUpperCase(Locale.ROOT);
        if (out.countryCode.isEmpty() && code.matches("[A-Z]{2}")) out.countryCode = code;
    }

    private void setIfEmpty(IpResult out, String field, String value) {
        value = clean(value);
        if (value.isEmpty()) return;
        if ("asn".equals(field) && out.asn.isEmpty()) out.asn = value;
        if ("org".equals(field) && out.org.isEmpty()) out.org = value;
        if ("networkType".equals(field) && out.networkType.isEmpty()) out.networkType = value;
        if ("timezone".equals(field) && out.timezone.isEmpty()) out.timezone = value;
    }

    private void setCoordinates(IpResult out, Object latitude, Object longitude) {
        String lat = clean(latitude == null ? "" : String.valueOf(latitude));
        String lon = clean(longitude == null ? "" : String.valueOf(longitude));
        if (out.coordinates.isEmpty() && !lat.isEmpty() && !lon.isEmpty()
                && !"0".equals(lat) && !"0".equals(lon)) out.coordinates = lat + ", " + lon;
    }

    private String joinLocation(String country, String region, String city) {
        StringBuilder out = new StringBuilder();
        append(out, "国家", clean(country));
        append(out, "地区", clean(region));
        append(out, "城市", clean(city));
        return out.length() == 0 ? "位置未返回" : out.toString();
    }

    private String joinJson(JSONArray values, String separator) {
        if (values == null) return "";
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < values.length(); i++) {
            String value = clean(String.valueOf(values.opt(i)));
            if (value.isEmpty() || "null".equalsIgnoreCase(value)) continue;
            if (out.length() > 0) out.append(separator);
            out.append(value);
        }
        return out.toString();
    }

    private String asnValue(Object value) {
        if (value instanceof JSONObject) value = ((JSONObject) value).opt("asn");
        return value == null ? "" : String.valueOf(value).replaceAll("[^0-9]", "");
    }

    private String addFreshness(String existing, String value) {
        value = clean(value);
        if (value.isEmpty()) return existing;
        if (existing == null || existing.trim().isEmpty()) return value;
        return existing.contains(value) ? existing : existing + "；" + value;
    }

    private String rdapEvents(JSONArray events) {
        if (events == null) return "";
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < events.length(); i++) {
            JSONObject event = events.optJSONObject(i);
            if (event == null) continue;
            String action = clean(event.optString("eventAction"));
            String date = clean(event.optString("eventDate"));
            if (action.isEmpty() && date.isEmpty()) continue;
            if (out.length() > 0) out.append("；");
            out.append(action.isEmpty() ? "事件" : action).append(" ").append(date);
        }
        return out.toString();
    }

    private String rdapEntities(JSONArray entities) {
        if (entities == null) return "";
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < entities.length() && i < 8; i++) {
            JSONObject entity = entities.optJSONObject(i);
            if (entity == null) continue;
            String handle = clean(entity.optString("handle"));
            String roles = joinJson(entity.optJSONArray("roles"), "/");
            if (handle.isEmpty() && roles.isEmpty()) continue;
            if (out.length() > 0) out.append("；");
            out.append(handle.isEmpty() ? "未命名实体" : handle);
            if (!roles.isEmpty()) out.append("(").append(roles).append(")");
        }
        return out.toString();
    }

    private String range(String start, String end) {
        if (start.isEmpty()) return end;
        if (end.isEmpty() || start.equals(end)) return start;
        return start + " – " + end;
    }

    private void append(StringBuilder out, String label, String value) {
        value = clean(value);
        if (value.isEmpty()) return;
        if (out.length() > 0) out.append("；");
        out.append(label).append(" ").append(value);
    }

    private String utcNow() {
        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss 'UTC'", Locale.US);
        format.setTimeZone(TimeZone.getTimeZone("UTC"));
        return format.format(new Date());
    }

    private String formatAsn(Object value) {
        String text = value == null ? "" : String.valueOf(value).trim();
        if (text.isEmpty() || "null".equalsIgnoreCase(text)) return "";
        return text.toUpperCase().startsWith("AS") ? text.toUpperCase() : "AS" + text;
    }

    private void parseFlatAsn(IpResult out, String value) {
        String text = clean(value);
        if (text.isEmpty()) return;
        String[] parts = text.split("\\s+", 2);
        setIfEmpty(out, "asn", formatAsn(parts[0]));
        if (parts.length > 1) setIfEmpty(out, "org", parts[1]);
    }

    private int toInt(Object value, int fallback) {
        try { return (int) Math.round(Double.parseDouble(String.valueOf(value))); }
        catch (Exception ignored) { return fallback; }
    }

    private boolean yes(String value) {
        String v = value == null ? "" : value.trim().toLowerCase();
        return "yes".equals(v) || "true".equals(v) || "1".equals(v);
    }

    private String enc(String value) throws Exception {
        return URLEncoder.encode(value, "UTF-8");
    }

    private String first(String one, String two) {
        return clean(one).isEmpty() ? clean(two) : clean(one);
    }

    private String clean(String value) {
        if (value == null || "null".equalsIgnoreCase(value.trim())) return "";
        return value.trim();
    }

    private String safeMessage(Exception e) {
        String message = e.getMessage();
        if (message == null || message.trim().isEmpty()) return e.getClass().getSimpleName();
        if (message.length() > 100) message = message.substring(0, 100);
        return message.replaceAll("apikey\\([^)]*\\)", "apikey(***)")
                .replaceAll("key=[^&\\s]+", "key=***");
    }

    private void throttleRdap() throws InterruptedException {
        synchronized (RDAP_RATE_LOCK) {
            long wait = 1050L - (System.currentTimeMillis() - lastRdapStarted);
            if (wait > 0) Thread.sleep(wait);
            lastRdapStarted = System.currentTimeMillis();
        }
    }

    private void applyConsensus(IpResult out, List<IpResult> values) {
        out.countryCode = consensus(values, "countryCode", out.countryCode);
        out.country = consensus(values, "country", out.country);
        out.region = consensus(values, "region", out.region);
        out.city = consensus(values, "city", out.city);
        out.asn = consensus(values, "asn", out.asn);
        out.org = consensus(values, "org", out.org);
        out.countryAgreement = agreement(values, "countryCode", out.countryCode);
        out.asnAgreement = agreement(values, "asn", out.asn);
    }

    private String consensus(List<IpResult> values, String field, String fallback) {
        Map<String, Integer> counts = new LinkedHashMap<>();
        Map<String, String> displays = new LinkedHashMap<>();
        for (IpResult value : values) {
            String display;
            if ("countryCode".equals(field)) display = value.countryCode;
            else if ("country".equals(field)) display = value.country;
            else if ("region".equals(field)) display = value.region;
            else if ("city".equals(field)) display = value.city;
            else if ("asn".equals(field)) display = value.asn;
            else display = value.org;
            display = clean(display);
            if (display.isEmpty()) continue;
            String key = ("countryCode".equals(field) || "asn".equals(field))
                    ? display.toUpperCase(Locale.ROOT) : display.toLowerCase(Locale.ROOT);
            counts.put(key, counts.containsKey(key) ? counts.get(key) + 1 : 1);
            if (!displays.containsKey(key)) displays.put(key, display);
        }
        int bestCount = 0;
        String best = fallback;
        for (String key : counts.keySet()) {
            int count = counts.get(key);
            if (count > bestCount) { bestCount = count; best = displays.get(key); }
        }
        return best;
    }

    private int agreement(List<IpResult> values, String field, String selected) {
        int count = 0;
        for (IpResult value : values) {
            String candidate = "countryCode".equals(field) ? value.countryCode : value.asn;
            if (!clean(selected).isEmpty() && clean(selected).equalsIgnoreCase(clean(candidate))) count++;
        }
        return count;
    }
}
