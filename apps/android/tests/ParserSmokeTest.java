package com.fool.ipbatch;

public final class ParserSmokeTest {
    public static void main(String[] args) {
        IpParser.ParseReport report = IpParser.parse("8.8.8.8, 8.8.8.8\n1.1.1.1:443 [2001:4860:4860::8888]:53 bad 999.1.1.1");
        check(report.ips.size() == 3, "应识别 3 个唯一 IP，实际 " + report.ips);
        check(report.duplicates == 1, "应识别重复项");
        check(report.rejected == 2, "应拒绝 2 个无效项，实际 " + report.rejected);
        check(!IpParser.isPublic("192.168.1.1"), "私网不应外发");
        check(!IpParser.isPublic("100.64.0.1"), "CGNAT 不应外发");
        check(IpParser.isPublic("8.8.8.8"), "公网应允许查询");
        IpParser.ParseReport cidr = IpParser.parse("203.0.114.0/24");
        check(cidr.ips.size() == 1 && cidr.cidrCollapsed == 1, "CIDR 应只取首址并记录");
        SubscriptionParser.Report yaml = SubscriptionParser.parse("proxies:\n"
                + "  - name: first\n    type: ss\n    server: 1.2.3.4\n    port: 443\n"
                + "  - {name: landing, type: vless, server: edge.example.com, port: 8443, dialer-proxy: first}\n");
        check(yaml.nodes.size() == 2, "应识别 YAML 两个节点，实际 " + yaml.nodes.size());
        check(yaml.chainReferences == 1, "应识别 dialer-proxy 链式引用");
        SubscriptionParser.Report providers = SubscriptionParser.parse("proxy-providers:\n  remote:\n    type: http\n    url: https://example.com/provider.yaml\n");
        check(providers.providerUrls.size() == 1, "应识别远程 proxy-provider URL");
        SubscriptionParser.Report base64 = SubscriptionParser.parse(
                "dmxlc3M6Ly8wMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDBAbm9kZS5leGFtcGxlLmNvbTo0NDMjZGVtbw==");
        check(base64.nodes.size() == 1 && "vless".equals(base64.nodes.get(0).protocol), "应识别 Base64 VLESS 订阅");
        check("node.example.com".equals(base64.nodes.get(0).host), "应提取节点域名");
        SubscriptionParser.Report vmess = SubscriptionParser.parse("vmess://eyJ2IjoiMiIsInBzIjoidjIiLCJhZGQiOiJ2bS5leGFtcGxlLmNvbSIsInBvcnQiOiI0NDMiLCJpZCI6IjAwMDAwMDAwLTAwMDAtMDAwMC0wMDAwLTAwMDAwMDAwMDAwMCIsImFpZCI6IjAiLCJuZXQiOiJ0Y3AiLCJ0eXBlIjoibm9uZSIsImhvc3QiOiIiLCJwYXRoIjoiIiwidGxzIjoiIn0=");
        check(vmess.nodes.size() == 1 && "vm.example.com".equals(vmess.nodes.get(0).host), "应识别 VMess v2 链接");
        SubscriptionParser.Report ss = SubscriptionParser.parse("ss://YWVzLTI1Ni1nY206cGFzc0Bzcy5leGFtcGxlLmNvbTo4Mzg4#ss");
        check(ss.nodes.size() == 1 && ss.nodes.get(0).port == 8388, "应识别 SIP002/兼容 SS 链接");
        SubscriptionParser.Report ssr = SubscriptionParser.parse("ssr://c3NyLmV4YW1wbGUuY29tOjQ0MzpvcmlnaW46YWVzLTI1Ni1jZmI6cGxhaW46Y0dGemN3PT0vP3JlbWFya3M9VTFOUw==");
        check(ssr.nodes.size() == 1 && "ssr.example.com".equals(ssr.nodes.get(0).host), "应识别 SSR 链接");
        SubscriptionParser.Report modern = SubscriptionParser.parse("trojan://pass@tr.example.com:443#tr\n"
                + "hy2://pass@hy.example.com:8443#hy\n"
                + "tuic://id:pass@tuic.example.com:443#tuic\n");
        check(modern.nodes.size() == 3, "应识别 Trojan/Hysteria2/TUIC 链接");
        IpResult us = new IpResult("8.8.8.8"); us.countryCode = "US"; us.riskEvaluated = true;
        String usPolicy = AiPolicyEvaluator.evaluate(us);
        check(usPolicy.contains("ChatGPT/OpenAI API：官方地区列表支持"), "美国出口应匹配 OpenAI 官方地区支持");
        IpResult hk = new IpResult("1.1.1.1"); hk.countryCode = "HK"; hk.datacenter = true; hk.riskEvaluated = true;
        String hkPolicy = AiPolicyEvaluator.evaluate(hk);
        check(hkPolicy.contains("ChatGPT/OpenAI API：官方支持列表未包含"), "香港出口不应误报 ChatGPT 官方支持");
        check(hkPolicy.contains("Gemini 网页：官方地区列表支持"), "香港出口应匹配 Gemini 网页支持");
        check(hkPolicy.contains("机房"), "机房风险应进入 AI 风控推断");
        IpResult cn = new IpResult("9.9.9.9"); cn.countryCode = "CN";
        check(AiPolicyEvaluator.evaluate(cn).contains("个人版不支持"), "中国大陆 Gemini 应标注 Workspace 例外");
        String original = "https://example.com/api/fsl64/path?token=a%2Fb&x=1&x=2";
        String alternate = SubscriptionDownloader.alternateFormatUrl(original);
        check("https://example.com/api/fslyaml/path?token=a%2Fb&x=1&x=2".equals(alternate), "fsl 格式切换必须保留原查询串");
        check(original.equals(SubscriptionDownloader.alternateFormatUrl(alternate)), "fsl 格式切换必须可往返");
        System.out.println("ParserSmokeTest OK");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
