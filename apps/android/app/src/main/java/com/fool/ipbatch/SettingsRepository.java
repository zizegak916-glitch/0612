package com.fool.ipbatch;

import android.content.Context;
import android.content.SharedPreferences;

public final class SettingsRepository {
    private SettingsRepository() {}

    public static ApiClient.Settings load(Context context) {
        SharedPreferences prefs = context.getSharedPreferences("sources", Context.MODE_PRIVATE);
        SecretStore secrets = new SecretStore(context);
        ApiClient.Settings settings = new ApiClient.Settings();
        settings.ipapi = prefs.getBoolean("ipapi", true);
        settings.proxyCheck = prefs.getBoolean("proxy", true);
        settings.geoJs = prefs.getBoolean("geo", true);
        settings.rdap = prefs.getBoolean("rdap", true);
        settings.ripeStat = prefs.getBoolean("ripe", true);
        settings.ping0 = prefs.getBoolean("ping0", false);
        settings.ipapiKey = value(secrets, prefs, "ipapi_key");
        settings.proxyCheckKey = value(secrets, prefs, "proxy_key");
        settings.ping0Key = value(secrets, prefs, "ping0_key");
        return settings;
    }

    public static boolean hasSource(ApiClient.Settings settings) {
        return settings.ipapi || settings.proxyCheck || settings.geoJs || settings.rdap || settings.ripeStat
                || (settings.ping0 && !settings.ping0Key.trim().isEmpty());
    }

    private static String value(SecretStore secrets, SharedPreferences prefs, String name) {
        String secure = secrets.get(name);
        return secure.isEmpty() ? prefs.getString(name, "") : secure;
    }
}
