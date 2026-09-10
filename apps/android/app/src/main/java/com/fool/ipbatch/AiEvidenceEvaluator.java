package com.fool.ipbatch;

/**
 * Renders evidence boundaries for AI-service investigations.
 *
 * An IP's geolocation and reputation are not a route test. This class deliberately
 * contains no country allow/deny list and never emits a supported/unsupported verdict.
 */
public final class AiEvidenceEvaluator {
    public static final String REFERENCE_DATE = "2026-09-09";
    public static final String OPENAI_API_POLICY_SOURCE =
            "https://developers.openai.com/api/docs/supported-countries";

    private AiEvidenceEvaluator() { }

    public static String evaluate(IpResult result) {
        String code = clean(result.countryCode);
        StringBuilder out = new StringBuilder();
        out.append("AI 可用性证据（不做支持/不支持判决）")
                .append("\n技术可用性：未测试。该 IP 只接受情报查询，未被设为设备路由，也未连接订阅节点。")
                .append("\n地理证据：")
                .append(code.isEmpty() ? "国家代码未知" : code)
                .append("；这是第三方数据库对 IP 的归属判断，不等于 ChatGPT 网页、OpenAI API 或账号地区。")
                .append("\n政策参考：OpenAI API 支持地区属于独立政策资料，不能用于推断 ChatGPT 网页是否能打开；")
                .append("本应用不再用内置国家黑名单自动定性。资料核对日期：")
                .append(REFERENCE_DATE).append("。")
                .append("\n官方来源：").append(OPENAI_API_POLICY_SOURCE)
                .append("\nIP 风险证据：").append(risk(result))
                .append("\n综合结论：仅凭该 IP 的国家代码、ASN、代理/VPN或机房标签，无法判断 GPT 可用或不可用。")
                .append("请以“当前设备 AI 入口观测”的带时间 HTTP 事实及人工登录/对话实测分别核验；两者冲突时全部保留，不互相覆盖。");
        return out.toString();
    }

    private static String risk(IpResult result) {
        if (result.tor || result.abuser || (result.riskScore != null && result.riskScore >= 67)) {
            return "数据源报告高风险特征；这只提示可能出现验证或风控，不证明平台不可用。";
        }
        if (result.proxy || result.vpn || result.datacenter || (result.riskScore != null && result.riskScore >= 34)) {
            return "数据源报告代理/VPN/机房或中风险特征；这不是封禁结论。";
        }
        if (!result.riskEvaluated) return "成功数据源未提供风险判定，不能声称低风险。";
        return "当前来源未报告明显风险；仍不能据此保证账号或模型可用。";
    }

    private static String clean(String value) {
        return value == null ? "" : value.trim().toUpperCase(java.util.Locale.ROOT);
    }
}
