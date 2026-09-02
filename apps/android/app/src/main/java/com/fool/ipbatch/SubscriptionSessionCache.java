package com.fool.ipbatch;

import java.util.ArrayList;
import java.util.List;

public final class SubscriptionSessionCache {
    private static String content = "";
    private static List<SubscriptionParser.NodeEndpoint> nodes = new ArrayList<>();

    private SubscriptionSessionCache() {}

    public static synchronized void set(String value, List<SubscriptionParser.NodeEndpoint> parsed) {
        content = value == null ? "" : value;
        nodes = parsed == null ? new ArrayList<SubscriptionParser.NodeEndpoint>() : new ArrayList<>(parsed);
    }

    public static synchronized void clear() { content = ""; nodes.clear(); }
    public static synchronized String content() { return content; }
    public static synchronized List<SubscriptionParser.NodeEndpoint> nodes() { return new ArrayList<>(nodes); }
}
