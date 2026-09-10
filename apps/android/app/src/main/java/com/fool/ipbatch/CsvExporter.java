package com.fool.ipbatch;

import java.util.List;

public final class CsvExporter {
    private CsvExporter() {}

    public static String create(List<IpResult> results) {
        StringBuilder out = new StringBuilder();
        out.append('\uFEFF');
        row(out, "IP", "来源/订阅节点", "状态", "最高风险分", "评分来源", "国家", "国家代码", "地区", "城市", "坐标", "时区",
                "ASN", "机构", "网络类型", "风险已评估", "VPN", "代理", "Tor", "机房", "滥用", "移动", "原生IP",
                "AI平台地区与风控推断", "RDAP注册", "BGP/RPKI路由", "时效字段", "可信度", "信号共识", "字段冲突", "成功源数", "总耗时ms", "逐来源证据", "逐来源明细", "错误");
        synchronized (results) {
            for (IpResult r : results) {
                row(out, r.ip, r.origin, r.status, r.riskScore == null ? "" : String.valueOf(r.riskScore), r.riskSource,
                        r.country, r.countryCode, r.region, r.city, r.coordinates, r.timezone, r.asn, r.org, r.networkType, yn(r.riskEvaluated),
                        yn(r.vpn), yn(r.proxy), yn(r.tor), yn(r.datacenter), yn(r.abuser), yn(r.mobile),
                        r.nativeIp == null ? "未知" : yn(r.nativeIp), AiEvidenceEvaluator.evaluate(r), r.registration, r.routing, r.freshness,
                        r.confidence, r.signalSummary, IpResult.join(r.conflicts, " | "),
                        String.valueOf(r.successfulSources), String.valueOf(r.durationMs()),
                        IpResult.join(r.sourceEvidence, " | "), IpResult.join(r.sourceDetails, " | "), IpResult.join(r.errors, " | "));
            }
        }
        return out.toString();
    }

    private static String yn(boolean value) { return value ? "是" : "否"; }

    private static void row(StringBuilder out, String... cells) {
        for (int i = 0; i < cells.length; i++) {
            if (i > 0) out.append(',');
            String value = cells[i] == null ? "" : cells[i];
            out.append('"').append(value.replace("\"", "\"\"")).append('"');
        }
        out.append("\r\n");
    }
}
