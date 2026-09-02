package com.fool.ipbatch;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

public final class AiPolicyEvaluator {
    public static final String POLICY_DATE = "2026-09-02";

    private static final Set<String> COMMON_SUPPORTED = set(
            "US,CA,GB,AU,NZ,JP,KR,TW,SG,IN,ID,MY,TH,VN,PH,DE,FR,NL,BE,LU,CH,AT,IT,ES,PT,IE," +
            "DK,SE,NO,FI,IS,PL,CZ,SK,SI,HR,RO,BG,GR,CY,MT,EE,LV,LT,UA,TR,IL,AE,SA,QA,KW,BH," +
            "OM,JO,LB,IQ,EG,MA,TN,DZ,ZA,NG,KE,GH,BR,AR,CL,CO,PE,MX,UY,PY,BO,EC,CR,PA,DO,JM");
    private static final Set<String> OPENAI_UNSUPPORTED = set("CN,HK,MO,RU,BY,IR,KP,CU,SY,VE");
    private static final Set<String> CLAUDE_UNSUPPORTED = set("CN,HK,MO,RU,BY,IR,KP,CU,SY,VE");
    private static final Set<String> GEMINI_CONSUMER_UNSUPPORTED = set("CN,RU,IR,KP,CU,SY");

    private AiPolicyEvaluator() {}

    public static String evaluate(IpResult result) {
        String code = result.countryCode == null ? "" : result.countryCode.trim().toUpperCase(Locale.ROOT);
        StringBuilder out = new StringBuilder();
        out.append("AI 地区政策快照（").append(POLICY_DATE).append("）：");
        if (code.isEmpty()) {
            out.append("国家代码缺失，无法做官方地区匹配");
        } else {
            out.append("\nChatGPT/OpenAI API：").append(policy(code, OPENAI_UNSUPPORTED, false));
            out.append("\nClaude：").append(policy(code, CLAUDE_UNSUPPORTED, false));
            out.append("\nGemini 网页：").append(policy(code, GEMINI_CONSUMER_UNSUPPORTED, "CN".equals(code)));
            out.append("\nGrok/xAI、Copilot、Perplexity：未维护同等粒度官方地区快照，仅以当前设备入口直测为准");
        }
        out.append("\nIP 风控推断：").append(risk(result));
        out.append("\n结论边界：这是地区政策与 IP 情报推断，不代表节点已实测解锁；账号、Cookie、支付区、手机号和平台实时风控仍会改变结果。");
        return out.toString();
    }

    private static String policy(String code, Set<String> unsupported, boolean workspaceOnly) {
        if (workspaceOnly) return "个人版不支持；官方列表仅标注 Workspace 场景";
        if (unsupported.contains(code)) return "官方支持列表未包含该地区（高概率不可用）";
        if (COMMON_SUPPORTED.contains(code) || "HK".equals(code) || "MO".equals(code)) return "官方地区列表支持";
        return "本地快照未覆盖该国家代码，需查看官方实时列表";
    }

    private static String risk(IpResult result) {
        if (result.tor || result.abuser || (result.riskScore != null && result.riskScore >= 67)) {
            return "高风险；即使地区支持，也可能遭遇验证、限流或封禁。";
        }
        if (result.proxy || result.vpn || result.datacenter || (result.riskScore != null && result.riskScore >= 34)) {
            return "存在代理/VPN/机房或中风险特征，可能触发平台风控。";
        }
        if (!result.riskEvaluated) return "成功数据源没有提供风险判定，不能评价低风险。";
        return "未发现显著风险标记，但不能据此保证账号可用。";
    }

    private static Set<String> set(String values) {
        return new HashSet<>(Arrays.asList(values.split(",")));
    }
}
