package com.fool.ipbatch;

public final class ConfigSmokeTest {
    public static void main(String[] args) throws Exception {
        SingBoxConfigBuilder builder = new SingBoxConfigBuilder();
        SingBoxConfigBuilder.Result vless = builder.build(
                "vless://11111111-1111-1111-1111-111111111111@1.1.1.1:443?security=tls&sni=example.com&type=ws&path=%2Fws#edge", "edge");
        if (args.length == 1 && "--print-vless".equals(args[0])) {
            System.out.print(vless.plans.get(0).config);
            return;
        }
        check(vless.plans.size() == 1, "VLESS plan count");
        String config = vless.plans.get(0).config;
        check(config.contains("\"type\":\"tun\""), "TUN inbound missing");
        check(config.contains("\"type\":\"vless\""), "VLESS outbound missing");
        check(config.contains("\"action\":\"reject\""), "private reject rule missing");

        String clash = "proxies:\n"
                + "  - name: edge\n    type: vless\n    server: 1.1.1.1\n    port: 443\n"
                + "    uuid: 11111111-1111-1111-1111-111111111111\n    tls: true\n    dialer-proxy: relay\n"
                + "  - {name: relay, type: ss, server: 8.8.8.8, port: 8388, cipher: aes-128-gcm, password: test}\n";
        SingBoxConfigBuilder.Result chained = builder.build(clash, "edge");
        if (args.length == 1 && "--print-chain".equals(args[0])) {
            System.out.print(chained.plans.get(0).config);
            return;
        }
        check(chained.plans.size() == 1, "Clash plan count");
        check(chained.plans.get(0).config.contains("\"detour\":\"chain-1\""), "dialer chain missing");

        boolean rejected = false;
        try { builder.build("trojan://secret@127.0.0.1:443#private", "private"); }
        catch (Exception expected) { rejected = true; }
        check(rejected, "private node was accepted");

        rejected = false;
        try { builder.build("ssr://Zm9v", ""); } catch (Exception expected) { rejected = true; }
        check(rejected, "SSR should be truthfully unsupported");
        System.out.println("ConfigSmokeTest OK");
    }

    private static void check(boolean value, String message) {
        if (!value) throw new AssertionError(message);
    }
}
