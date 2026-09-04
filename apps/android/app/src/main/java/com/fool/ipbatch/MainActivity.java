package com.fool.ipbatch;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.text.InputType;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.HorizontalScrollView;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import org.json.JSONObject;

public final class MainActivity extends Activity {
    private static final int EXPORT_REQUEST = 41;
    private static final int BLUE = Color.rgb(55, 107, 255);
    private static final int INK = Color.rgb(23, 32, 51);
    private static final int MUTED = Color.rgb(102, 113, 133);
    private static final int SURFACE = Color.rgb(245, 247, 251);

    private EditText input;
    private EditText subscriptionInput;
    private CheckBox saveSubscription;
    private CheckBox allowPrivateSubscription;
    private TextView subscriptionStatus;
    private TextView networkStatus;
    private Button startButton;
    private Button cancelButton;
    private Button exportButton;
    private Button exitButton;
    private Button subscriptionButton;
    private Button viewNodesButton;
    private Button viewRawButton;
    private Button aiTestButton;
    private TextView aiTestStatus;
    private Button detailButton;
    private Button realTestButton;
    private TextView advancedStatus;
    private ProgressBar progress;
    private TextView summary;
    private LinearLayout resultContainer;
    private TextView emptyState;
    private EditText resultSearch;
    private SecretStore secretStore;
    private SavedSubscriptionStore subscriptionStore;

    private final List<IpResult> results = Collections.synchronizedList(new ArrayList<IpResult>());
    private final Map<String, ResultViews> resultViews = new LinkedHashMap<>();
    private final Map<String, String> pendingOrigins = new LinkedHashMap<>();
    private String pendingCsv;
    private String lastSubscriptionContent = "";
    private List<SubscriptionParser.NodeEndpoint> lastSubscriptionNodes = new ArrayList<>();
    private String scanLabel = "手动输入";
    private int total;
    private boolean scanRunning;
    private boolean scanReceiverRegistered;
    private String resultStatusFilter = "全部";

    private final BroadcastReceiver scanReceiver = new BroadcastReceiver() {
        @Override public void onReceive(Context context, Intent intent) {
            if (AiTestForegroundService.ACTION_STATE.equals(intent.getAction())) handleAiBroadcast(intent);
            else if (AdvancedTestForegroundService.ACTION_STATE.equals(intent.getAction())) restoreAdvancedState();
            else if (ScanForegroundService.ACTION_SUBSCRIPTION_STATE.equals(intent.getAction())) handleSubscriptionBroadcast(intent);
            else if (ScanForegroundService.ACTION_EXIT_STATE.equals(intent.getAction())) handleExitBroadcast(intent);
            else handleScanBroadcast(intent);
        }
    };

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        secretStore = new SecretStore(this);
        subscriptionStore = new SavedSubscriptionStore(secretStore);
        String legacySubscription = secretStore.get("subscription_url");
        if (!legacySubscription.isEmpty() && subscriptionStore.list().isEmpty()) {
            try { subscriptionStore.save(legacySubscription); } catch (Exception ignored) { }
        }
        buildUi();
        if (state != null) {
            input.setText(state.getString("input", ""));
            String transientSub = state.getString("subscription", "");
            if (!transientSub.isEmpty()) subscriptionInput.setText(transientSub);
        }
        refreshNetworkState();
    }

    @Override protected void onStart() {
        super.onStart();
        IntentFilter filter = new IntentFilter(ScanForegroundService.ACTION_SCAN_STATE);
        filter.addAction(AiTestForegroundService.ACTION_STATE);
        filter.addAction(AdvancedTestForegroundService.ACTION_STATE);
        filter.addAction(ScanForegroundService.ACTION_SUBSCRIPTION_STATE);
        filter.addAction(ScanForegroundService.ACTION_EXIT_STATE);
        if (Build.VERSION.SDK_INT >= 33) registerReceiver(scanReceiver, filter, Context.RECEIVER_NOT_EXPORTED);
        else registerReceiver(scanReceiver, filter);
        scanReceiverRegistered = true;
        restoreScanState();
        restoreAiState();
        restoreAdvancedState();
        restoreSubscriptionSession();
    }

    @Override protected void onStop() {
        if (scanReceiverRegistered) {
            try { unregisterReceiver(scanReceiver); } catch (Exception ignored) { }
            scanReceiverRegistered = false;
        }
        super.onStop();
    }

    @Override protected void onSaveInstanceState(Bundle out) {
        super.onSaveInstanceState(out);
        out.putString("input", input.getText().toString());
        out.putString("subscription", subscriptionInput.getText().toString());
    }

    private void buildUi() {
        LinearLayout root = column();
        root.setBackgroundColor(SURFACE);

        LinearLayout header = column();
        header.setPadding(dp(20), dp(18), dp(20), dp(14));
        header.setBackgroundColor(Color.WHITE);
        header.addView(label("IP系统情报", 25, INK, Typeface.BOLD));
        TextView subtitle = label("系统出口 · 订阅服务器IP · 注册/路由/风险多源交叉", 13, MUTED, Typeface.NORMAL);
        subtitle.setPadding(0, dp(4), 0, 0);
        header.addView(subtitle);
        root.addView(header, matchWrap());

        ScrollView scroll = new ScrollView(this);
        LinearLayout content = column();
        content.setPadding(dp(16), dp(16), dp(16), dp(28));

        LinearLayout networkCard = card();
        networkCard.addView(label("设备当前系统路由", 17, INK, Typeface.BOLD));
        networkStatus = label("正在读取系统网络状态…", 12, MUTED, Typeface.NORMAL);
        networkStatus.setPadding(0, dp(7), 0, dp(9));
        networkCard.addView(networkStatus);
        LinearLayout networkActions = row();
        exitButton = primaryButton("识别并体检当前出口");
        Button refreshNetwork = secondaryButton("刷新路由状态");
        networkActions.addView(exitButton, buttonParams());
        networkActions.addView(refreshNetwork, buttonParams());
        networkCard.addView(networkActions);
        TextView exitNote = label("出口检测只在你点击后执行，结果代表本应用经 Android 系统默认路由访问外网时看到的 IPv4/IPv6；分应用代理可能使它与其他应用不同。", 11, MUTED, Typeface.NORMAL);
        exitNote.setPadding(0, dp(8), 0, 0);
        networkCard.addView(exitNote);
        content.addView(networkCard, spaced());

        LinearLayout aiCard = card();
        aiCard.addView(label("AI 平台可用性", 17, INK, Typeface.BOLD));
        TextView aiHint = label("通过当前设备的 Android 系统默认路由，直接访问 ChatGPT/OpenAI、Claude、Gemini/AI Studio、Grok/xAI、Copilot、Perplexity 的公开入口。网页与 API 分开检测；不发送账号、Cookie、API Key或提示词。", 12, MUTED, Typeface.NORMAL);
        aiHint.setPadding(0, dp(5), 0, dp(9)); aiCard.addView(aiHint);
        aiTestButton = primaryButton("后台直测 AI 平台"); aiCard.addView(aiTestButton, buttonParams());
        aiTestStatus = label("尚未直测。HTTP 可达只证明平台入口响应，不保证登录、账号、支付或具体模型可用。", 11, MUTED, Typeface.NORMAL);
        aiTestStatus.setTextIsSelectable(true); aiTestStatus.setPadding(0, dp(8), 0, 0); aiCard.addView(aiTestStatus);
        content.addView(aiCard, spaced());

        LinearLayout advancedCard = card();
        advancedCard.addView(label("高级网络调查", 17, INK, Typeface.BOLD));
        TextView advancedHint = label("详细调查一次只接收 1 个公网 IP，汇集 RDAP、RIPEstat、Shodan InternetDB、GreyNoise、PTR 与 443/TLS 证书；真实测试读取订阅节点名，控制本机 Mihomo/Clash 的回环 API，逐节点通过已开启的 Android 系统 VPN 访问真实 AI 对话网址。", 12, MUTED, Typeface.NORMAL);
        advancedHint.setPadding(0, dp(5), 0, dp(9)); advancedCard.addView(advancedHint);
        LinearLayout advancedActions = row();
        detailButton = primaryButton("单 IP 详细调查"); realTestButton = secondaryButton("订阅真实测试");
        advancedActions.addView(detailButton, buttonParams()); advancedActions.addView(realTestButton, buttonParams());
        advancedCard.addView(advancedActions);
        advancedStatus = label("尚未运行。详细模式只主动连接目标 443/TCP；真实测试会临时改变系统 VPN 的策略组节点，并在普通测试结束时恢复。", 11, MUTED, Typeface.NORMAL);
        advancedStatus.setTextIsSelectable(true); advancedStatus.setPadding(0, dp(8), 0, 0); advancedCard.addView(advancedStatus);
        content.addView(advancedCard, spaced());

        LinearLayout subCard = card();
        subCard.addView(label("订阅链接批量体检", 17, INK, Typeface.BOLD));
        TextView subHint = label("只下载订阅、解析节点服务器、执行 DNS 与 IP 情报查询；绝不连接节点端口，不做协议握手，不切换系统代理。支持 Clash/Mihomo YAML、Base64、SS/SSR、VMess、VLESS、Trojan、Hysteria、Hysteria2、TUIC、SOCKS/HTTP URI。", 12, MUTED, Typeface.NORMAL);
        subHint.setPadding(0, dp(5), 0, dp(10));
        subCard.addView(subHint);
        subscriptionInput = new EditText(this);
        subscriptionInput.setHint("https://example.com/subscribe?token=…");
        subscriptionInput.setTextSize(14);
        subscriptionInput.setSingleLine(true);
        subscriptionInput.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
        subscriptionInput.setPadding(dp(13), dp(10), dp(13), dp(10));
        subscriptionInput.setBackground(rounded(Color.WHITE, Color.rgb(215, 221, 232), 12, 1));
        String savedSubscription = secretStore.get("subscription_url");
        if (savedSubscription.isEmpty()) savedSubscription = subscriptionStore.firstUrl();
        if (!savedSubscription.isEmpty()) subscriptionInput.setText(savedSubscription);
        subCard.addView(subscriptionInput, matchWrap());
        saveSubscription = checkbox("在本机加密保存订阅链接", secretStore.contains("subscription_url"));
        subCard.addView(saveSubscription);
        allowPrivateSubscription = checkbox("允许访问本机/局域网订阅（127.0.0.1、路由器、私网地址）",
                prefs().getBoolean("allow_private_subscription", false));
        subCard.addView(allowPrivateSubscription);
        TextView privateHint = label("开启后，HTTP 也只允许私网目标；公网订阅仍强制 HTTPS。解析出的私网节点 IP 仍不会发送给外部情报接口。", 11, Color.rgb(174, 101, 24), Typeface.NORMAL);
        privateHint.setPadding(0, 0, 0, dp(6));
        subCard.addView(privateHint);
        HorizontalScrollView subActionScroll = new HorizontalScrollView(this);
        subActionScroll.setHorizontalScrollBarEnabled(false);
        LinearLayout subActions = row();
        subscriptionButton = primaryButton("下载、解析并检测");
        Button removeSaved = secondaryButton("删除已保存链接");
        Button manageSaved = secondaryButton("管理已保存订阅");
        viewNodesButton = secondaryButton("查看节点清单");
        viewRawButton = secondaryButton("查看订阅原文");
        viewNodesButton.setEnabled(false);
        viewRawButton.setEnabled(false);
        subActions.addView(subscriptionButton, buttonParams());
        subActions.addView(viewNodesButton, buttonParams());
        subActions.addView(viewRawButton, buttonParams());
        subActions.addView(manageSaved, buttonParams());
        subActions.addView(removeSaved, buttonParams());
        subActionScroll.addView(subActions);
        subCard.addView(subActionScroll);
        subscriptionStatus = label("尚未读取订阅。完整链接可能包含凭证，不会写入日志或导出文件。", 11, MUTED, Typeface.NORMAL);
        subscriptionStatus.setTextIsSelectable(true);
        subscriptionStatus.setPadding(0, dp(8), 0, 0);
        subCard.addView(subscriptionStatus);
        content.addView(subCard, spaced());

        LinearLayout inputCard = card();
        inputCard.addView(label("手动 IP 列表", 17, INK, Typeface.BOLD));
        TextView inputHint = label("支持换行、逗号、IPv4:端口、[IPv6]:端口；最多 500 个。CIDR 只取首个地址。", 12, MUTED, Typeface.NORMAL);
        inputHint.setPadding(0, dp(5), 0, dp(10));
        inputCard.addView(inputHint);
        input = new EditText(this);
        input.setHint("8.8.8.8\n1.1.1.1\n2001:4860:4860::8888");
        input.setTextSize(15);
        input.setTextColor(INK);
        input.setHintTextColor(Color.rgb(160, 168, 184));
        input.setGravity(Gravity.TOP | Gravity.START);
        input.setMinHeight(dp(120));
        input.setPadding(dp(13), dp(11), dp(13), dp(11));
        input.setBackground(rounded(Color.WHITE, Color.rgb(215, 221, 232), 12, 1));
        inputCard.addView(input, matchWrap());

        HorizontalScrollView actionScroll = new HorizontalScrollView(this);
        actionScroll.setHorizontalScrollBarEnabled(false);
        LinearLayout actions = row();
        actions.setPadding(0, dp(12), 0, 0);
        startButton = primaryButton("检测手动列表");
        cancelButton = secondaryButton("取消");
        cancelButton.setEnabled(false);
        Button clearButton = secondaryButton("清空");
        Button settingsButton = secondaryButton("数据源设置");
        actions.addView(startButton, buttonParams());
        actions.addView(cancelButton, buttonParams());
        actions.addView(clearButton, buttonParams());
        actions.addView(settingsButton, buttonParams());
        actionScroll.addView(actions);
        inputCard.addView(actionScroll, matchWrap());
        content.addView(inputCard, spaced());

        LinearLayout progressCard = card();
        summary = label("尚未开始", 14, INK, Typeface.BOLD);
        progress = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal);
        progress.setMax(100);
        progress.setProgressTintList(ColorStateList.valueOf(BLUE));
        progress.setPadding(0, dp(9), 0, dp(2));
        progressCard.addView(summary);
        progressCard.addView(progress, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(18)));
        content.addView(progressCard, spaced());

        LinearLayout resultHeader = row();
        resultHeader.setGravity(Gravity.CENTER_VERTICAL);
        resultHeader.addView(label("详细结果", 18, INK, Typeface.BOLD), new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1));
        exportButton = secondaryButton("导出详细 CSV");
        exportButton.setEnabled(false);
        resultHeader.addView(exportButton, buttonParams());
        content.addView(resultHeader);

        resultSearch = new EditText(this);
        resultSearch.setHint("筛选 IP、国家、ASN、机构、节点名"); resultSearch.setSingleLine(true); resultSearch.setTextSize(13);
        resultSearch.setPadding(dp(12), dp(8), dp(12), dp(8));
        resultSearch.setBackground(rounded(Color.WHITE, Color.rgb(215, 221, 232), 12, 1));
        content.addView(resultSearch, matchWrap());
        HorizontalScrollView resultActionScroll = new HorizontalScrollView(this); resultActionScroll.setHorizontalScrollBarEnabled(false);
        LinearLayout resultActions = row(); resultActions.setPadding(0, dp(8), 0, dp(8));
        Button applyFilter = secondaryButton("应用筛选"); Button chooseFilter = secondaryButton("状态：全部");
        Button sortRisk = secondaryButton("风险优先排序"); Button history = secondaryButton("历史与对比");
        Button resetFilter = secondaryButton("重置筛选");
        resultActions.addView(applyFilter, buttonParams()); resultActions.addView(chooseFilter, buttonParams());
        resultActions.addView(sortRisk, buttonParams()); resultActions.addView(history, buttonParams());
        resultActions.addView(resetFilter, buttonParams()); resultActionScroll.addView(resultActions);
        content.addView(resultActionScroll, matchWrap());

        resultContainer = column();
        emptyState = label("每个字段都会标记来源；注册、BGP/RPKI、位置、风险和最后观测时间不会被混成一个伪精确结论。", 13, MUTED, Typeface.NORMAL);
        emptyState.setGravity(Gravity.CENTER);
        emptyState.setPadding(dp(16), dp(36), dp(16), dp(36));
        resultContainer.addView(emptyState);
        content.addView(resultContainer, matchWrap());

        scroll.addView(content);
        root.addView(scroll, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1));
        setContentView(root);

        startButton.setOnClickListener(new View.OnClickListener() { @Override public void onClick(View v) {
            pendingOrigins.clear(); scanLabel = "手动输入"; startScan();
        }});
        cancelButton.setOnClickListener(new View.OnClickListener() { @Override public void onClick(View v) { cancelScan(); }});
        clearButton.setOnClickListener(new View.OnClickListener() { @Override public void onClick(View v) { if (!isRunning()) clearAll(); }});
        settingsButton.setOnClickListener(new View.OnClickListener() { @Override public void onClick(View v) { if (!isRunning()) showSettings(); }});
        exportButton.setOnClickListener(new View.OnClickListener() { @Override public void onClick(View v) { exportCsv(); }});
        applyFilter.setOnClickListener(new View.OnClickListener() { @Override public void onClick(View v) { applyResultFilter(); }});
        chooseFilter.setOnClickListener(new View.OnClickListener() { @Override public void onClick(View v) { showResultFilterDialog(chooseFilter); }});
        sortRisk.setOnClickListener(new View.OnClickListener() { @Override public void onClick(View v) { sortResultsByRisk(); }});
        history.setOnClickListener(new View.OnClickListener() { @Override public void onClick(View v) { showScanHistory(); }});
        resetFilter.setOnClickListener(new View.OnClickListener() { @Override public void onClick(View v) {
            resultStatusFilter = "全部"; chooseFilter.setText("状态：全部"); resultSearch.setText(""); applyResultFilter();
        }});
        exitButton.setOnClickListener(new View.OnClickListener() { @Override public void onClick(View v) { detectCurrentExit(); }});
        refreshNetwork.setOnClickListener(new View.OnClickListener() { @Override public void onClick(View v) { refreshNetworkState(); }});
        subscriptionButton.setOnClickListener(new View.OnClickListener() { @Override public void onClick(View v) { inspectSubscription(); }});
        aiTestButton.setOnClickListener(new View.OnClickListener() { @Override public void onClick(View v) { startAiTest(); }});
        detailButton.setOnClickListener(new View.OnClickListener() { @Override public void onClick(View v) { showDetailDialog(); }});
        realTestButton.setOnClickListener(new View.OnClickListener() { @Override public void onClick(View v) { showRealTestDialog(); }});
        viewNodesButton.setOnClickListener(new View.OnClickListener() { @Override public void onClick(View v) { showSubscriptionNodes(); }});
        viewRawButton.setOnClickListener(new View.OnClickListener() { @Override public void onClick(View v) { showSubscriptionRaw(); }});
        manageSaved.setOnClickListener(new View.OnClickListener() { @Override public void onClick(View v) { showSavedSubscriptions(); }});
        removeSaved.setOnClickListener(new View.OnClickListener() { @Override public void onClick(View v) {
            String current = subscriptionInput.getText().toString().trim();
            try { subscriptionStore.remove(current); } catch (Exception ignored) { }
            if (secretStore.get("subscription_url").equals(current)) secretStore.remove("subscription_url");
            saveSubscription.setChecked(false); subscriptionInput.setText("");
            lastSubscriptionContent = ""; lastSubscriptionNodes.clear();
            viewNodesButton.setEnabled(false); viewRawButton.setEnabled(false);
            toast("已删除本机保存的订阅链接");
        }});
    }

    private void refreshNetworkState() { networkStatus.setText(NetworkStateReader.describe(this)); }

    private void detectCurrentExit() {
        if (isRunning()) return;
        prepareForBackgroundTask(); scanRunning = true;
        exitButton.setEnabled(false); subscriptionButton.setEnabled(false); cancelButton.setEnabled(true);
        summary.setText("出口识别已交给系统后台服务…"); requestNotificationPermission();
        Intent service = new Intent(this, ScanForegroundService.class).setAction(ScanForegroundService.ACTION_START_EXIT);
        try {
            if (Build.VERSION.SDK_INT >= 26) startForegroundService(service); else startService(service);
            startAiTest();
        } catch (Exception e) { scanRunning = false; finishUi(); summary.setText("出口后台服务启动失败：" + safe(e)); }
    }

    private void inspectSubscription() {
        if (isRunning()) return;
        final String url = subscriptionInput.getText().toString().trim();
        if (url.isEmpty()) { toast("请填写订阅链接"); return; }
        if (saveSubscription.isChecked()) {
            try { secretStore.put("subscription_url", url); subscriptionStore.save(url); }
            catch (Exception e) { toast("加密保存失败，但仍会执行本次检测"); }
        }
        final boolean allowPrivate = allowPrivateSubscription.isChecked();
        prefs().edit().putBoolean("allow_private_subscription", allowPrivate).apply();
        lastSubscriptionContent = ""; lastSubscriptionNodes.clear();
        SubscriptionSessionCache.clear();
        viewNodesButton.setEnabled(false); viewRawButton.setEnabled(false);
        exitButton.setEnabled(false); subscriptionButton.setEnabled(false);
        scanRunning = true;
        prepareForBackgroundTask(); scanRunning = true;
        subscriptionStatus.setText("订阅已交给系统后台服务下载和解析；不会连接任何节点端口…");
        summary.setText("后台服务正在准备订阅检测…");
        final String userAgent = prefs().getString("subscription_ua", "Clash.Meta");
        requestNotificationPermission();
        Intent service = new Intent(this, ScanForegroundService.class).setAction(ScanForegroundService.ACTION_START_SUBSCRIPTION);
        service.putExtra(ScanForegroundService.EXTRA_URL, url); service.putExtra(ScanForegroundService.EXTRA_USER_AGENT, userAgent);
        service.putExtra(ScanForegroundService.EXTRA_ALLOW_PRIVATE, allowPrivate);
        try { if (Build.VERSION.SDK_INT >= 26) startForegroundService(service); else startService(service); }
        catch (Exception e) {
            scanRunning = false; finishUi(); subscriptionStatus.setText("订阅后台服务启动失败：" + safe(e));
        }
    }

    private void showSubscriptionNodes() {
        if (lastSubscriptionNodes.isEmpty()) { toast("尚无可查看的节点清单"); return; }
        StringBuilder text = new StringBuilder();
        text.append("共 ").append(lastSubscriptionNodes.size()).append(" 个解析节点。这里只展示协议、名称、服务器和端口，不展示密码、UUID或订阅凭证。\n\n");
        for (int i = 0; i < lastSubscriptionNodes.size(); i++) {
            SubscriptionParser.NodeEndpoint node = lastSubscriptionNodes.get(i);
            text.append(i + 1).append(". ").append(node.protocol.toUpperCase(Locale.ROOT));
            if (!node.name.isEmpty()) text.append(" · ").append(node.name);
            text.append("\n   ").append(node.host);
            if (node.port > 0) text.append(":").append(node.port);
            text.append("\n");
        }
        showTextDialog("订阅节点清单（已脱敏）", text.toString());
    }

    private void showSubscriptionRaw() {
        if (lastSubscriptionContent.isEmpty()) { toast("尚无可查看的订阅原文"); return; }
        String content = lastSubscriptionContent;
        if (content.length() > 1500000) content = content.substring(0, 1500000)
                + "\n\n[界面预览在 1,500,000 字符处截断；下载和解析使用的是完整内容]";
        showTextDialog("订阅原文（包含敏感凭证）",
                "警告：原文可能含密码、UUID、Token和节点密钥。内容只保存在当前进程内，不写入本机存储或导出文件。\n\n" + content);
    }

    private void showSavedSubscriptions() {
        final List<SavedSubscriptionStore.Entry> entries = subscriptionStore.list();
        if (entries.isEmpty()) { toast("尚未保存任何订阅"); return; }
        final LinearLayout list = column(); list.setPadding(dp(16), dp(6), dp(16), dp(12));
        final AlertDialog[] holder = new AlertDialog[1];
        for (final SavedSubscriptionStore.Entry entry : entries) {
            final LinearLayout item = card();
            TextView name = label(entry.label, 14, INK, Typeface.BOLD);
            TextView hint = label("完整链接已加密，不在列表中显示 Token；载入后会回填输入框。", 11, MUTED, Typeface.NORMAL);
            LinearLayout actions = row();
            Button load = primaryButton("载入"); Button delete = secondaryButton("删除");
            actions.addView(load, buttonParams()); actions.addView(delete, buttonParams());
            item.addView(name); item.addView(hint); item.addView(actions); list.addView(item, spaced());
            load.setOnClickListener(new View.OnClickListener() { @Override public void onClick(View v) {
                subscriptionInput.setText(entry.url); saveSubscription.setChecked(true);
                if (holder[0] != null) holder[0].dismiss();
            }});
            delete.setOnClickListener(new View.OnClickListener() { @Override public void onClick(View v) {
                try { subscriptionStore.remove(entry.url); item.setVisibility(View.GONE); toast("已删除该订阅"); }
                catch (Exception e) { toast("删除失败"); }
            }});
        }
        ScrollView scroll = new ScrollView(this); scroll.addView(list);
        holder[0] = new AlertDialog.Builder(this).setTitle("已保存订阅（最多 20 个）")
                .setView(scroll).setPositiveButton("关闭", null).create();
        holder[0].show();
    }

    private void showTextDialog(String title, String text) {
        ScrollView scroll = new ScrollView(this);
        TextView content = label(text, 12, INK, Typeface.NORMAL);
        content.setTextIsSelectable(true);
        content.setTypeface(Typeface.MONOSPACE);
        content.setPadding(dp(18), dp(12), dp(18), dp(18));
        scroll.addView(content);
        AlertDialog dialog = new AlertDialog.Builder(this).setTitle(title).setView(scroll)
                .setPositiveButton("关闭", null).create();
        dialog.show();
    }

    private void startScan() {
        IpParser.ParseReport parsed = IpParser.parse(input.getText().toString());
        if (parsed.ips.isEmpty()) { toast("没有识别到有效 IP"); return; }
        final ApiClient.Settings settings = SettingsRepository.load(this);
        if (!SettingsRepository.hasSource(settings)) { toast("请至少启用一个数据源"); return; }
        if (!networkAvailable()) toast("当前网络可能不可用，仍会处理本地拦截规则");
        results.clear(); resultViews.clear(); resultContainer.removeAllViews();
        total = parsed.ips.size(); progress.setProgress(0); scanRunning = true;
        startButton.setEnabled(false); cancelButton.setEnabled(true); exportButton.setEnabled(false);
        exitButton.setEnabled(false); subscriptionButton.setEnabled(false);
        for (String ip : parsed.ips) {
            IpResult pending = new IpResult(ip);
            pending.origin = pendingOrigins.containsKey(ip) ? pendingOrigins.get(ip) : scanLabel;
            results.add(pending); resultViews.put(ip, addResultCard(pending));
        }
        String notes = scanLabel + " · 共 " + total + " 个";
        if (parsed.duplicates > 0) notes += "，去重 " + parsed.duplicates;
        if (parsed.rejected > 0) notes += "，无效 " + parsed.rejected;
        if (parsed.cidrCollapsed > 0) notes += "，CIDR取首址 " + parsed.cidrCollapsed;
        if (parsed.truncated > 0) notes += "，超限 " + parsed.truncated;
        summary.setText(notes + " · 后台服务检测中 0/" + total);
        requestNotificationPermission();
        try {
            JSONObject origins = new JSONObject();
            for (Map.Entry<String, String> entry : pendingOrigins.entrySet()) origins.put(entry.getKey(), entry.getValue());
            Intent service = new Intent(this, ScanForegroundService.class).setAction(ScanForegroundService.ACTION_START_SCAN);
            service.putStringArrayListExtra(ScanForegroundService.EXTRA_IPS, new ArrayList<>(parsed.ips));
            service.putExtra(ScanForegroundService.EXTRA_ORIGINS, origins.toString());
            service.putExtra(ScanForegroundService.EXTRA_LABEL, scanLabel);
            if (Build.VERSION.SDK_INT >= 26) startForegroundService(service); else startService(service);
        } catch (Exception e) {
            scanRunning = false; finishUi(); summary.setText("后台服务启动失败：" + safe(e));
        }
    }

    private void handleScanBroadcast(Intent intent) {
        if (intent == null || !ScanForegroundService.ACTION_SCAN_STATE.equals(intent.getAction())) return;
        String encoded = intent.getStringExtra(ScanForegroundService.EXTRA_RESULT);
        if (encoded != null && !encoded.isEmpty()) try {
            IpResult incoming = ScanStateStore.decodeResult(new JSONObject(encoded));
            boolean found = false;
            for (IpResult current : results) if (current.ip.equals(incoming.ip)) { copy(incoming, current); found = true; break; }
            if (!found) {
                results.add(incoming); resultViews.put(incoming.ip, addResultCard(incoming));
                String currentInput = input.getText().toString();
                input.setText(currentInput.isEmpty() ? incoming.ip : currentInput + "\n" + incoming.ip);
            }
            ResultViews views = resultViews.get(incoming.ip);
            if (views != null) {
                for (IpResult current : results) if (current.ip.equals(incoming.ip)) { bind(views, current); break; }
            }
        } catch (Exception ignored) { }
        total = intent.getIntExtra(ScanForegroundService.EXTRA_TOTAL, total);
        String liveLabel = intent.getStringExtra(ScanForegroundService.EXTRA_LABEL);
        if (liveLabel != null && !liveLabel.isEmpty()) scanLabel = liveLabel;
        int now = intent.getIntExtra(ScanForegroundService.EXTRA_COMPLETED, 0);
        scanRunning = intent.getBooleanExtra(ScanForegroundService.EXTRA_RUNNING, false);
        updateSummary(now);
        if (!scanRunning && total > 0) finishUi();
    }

    private void handleSubscriptionBroadcast(Intent intent) {
        String error = intent.getStringExtra(ScanForegroundService.EXTRA_SUBSCRIPTION_ERROR);
        String detail = intent.getStringExtra(ScanForegroundService.EXTRA_SUBSCRIPTION_SUMMARY);
        boolean ready = intent.getBooleanExtra(ScanForegroundService.EXTRA_SUBSCRIPTION_READY, false);
        if (error != null && !error.isEmpty()) {
            SubscriptionSessionCache.clear(); lastSubscriptionContent = ""; lastSubscriptionNodes.clear();
            viewNodesButton.setEnabled(false); viewRawButton.setEnabled(false);
            subscriptionStatus.setText("订阅处理失败：" + error); summary.setText("订阅后台处理失败"); finishUi(); return;
        }
        if (detail != null && !detail.isEmpty()) subscriptionStatus.setText(detail);
        if (ready) {
            restoreSubscriptionSession();
            summary.setText("订阅解析完成，后台服务正在检测唯一公网 IP…");
        }
    }

    private void handleExitBroadcast(Intent intent) {
        String error = intent.getStringExtra(ScanForegroundService.EXTRA_EXIT_ERROR);
        String detail = intent.getStringExtra(ScanForegroundService.EXTRA_EXIT_SUMMARY);
        refreshNetworkState();
        if (error != null && !error.isEmpty()) {
            summary.setText("出口识别失败：" + error); finishUi(); return;
        }
        if (detail != null && !detail.isEmpty()) summary.setText("已识别当前出口：" + detail + "；正在后台查询详细情报");
    }

    private void restoreSubscriptionSession() {
        String content = SubscriptionSessionCache.content();
        List<SubscriptionParser.NodeEndpoint> nodes = SubscriptionSessionCache.nodes();
        if (content.isEmpty() && nodes.isEmpty()) return;
        lastSubscriptionContent = content; lastSubscriptionNodes = nodes;
        viewRawButton.setEnabled(!content.isEmpty()); viewNodesButton.setEnabled(!nodes.isEmpty());
    }

    private void startAiTest() {
        requestNotificationPermission();
        aiTestButton.setEnabled(false); aiTestStatus.setText("AI 平台直测已交给后台服务；切换应用或锁屏后仍会继续…");
        Intent service = new Intent(this, AiTestForegroundService.class).setAction(AiTestForegroundService.ACTION_START);
        try {
            if (Build.VERSION.SDK_INT >= 26) startForegroundService(service); else startService(service);
        } catch (Exception e) {
            aiTestButton.setEnabled(true); aiTestStatus.setText("AI 直测服务启动失败：" + safe(e));
        }
    }

    private void handleAiBroadcast(Intent intent) {
        boolean running = intent.getBooleanExtra(AiTestForegroundService.EXTRA_RUNNING, false);
        aiTestButton.setEnabled(!running); restoreAiState();
    }

    private void restoreAiState() {
        if (aiTestStatus == null) return;
        AiReportStore.State state = AiReportStore.load(this);
        if (state == null || state.report.checks.isEmpty()) return;
        aiTestButton.setEnabled(!state.running);
        StringBuilder text = new StringBuilder();
        text.append(state.running ? "后台检测中" : state.report.summary()).append("\n");
        synchronized (state.report.checks) {
            for (AiReachabilityTester.Check check : state.report.checks) {
                text.append("\n").append(check.platform).append(" ").append(check.surface).append("：")
                        .append(check.status).append(" · ").append(check.detail)
                        .append(" · ").append(check.durationMs).append(" ms")
                        .append("\n  ").append(check.host);
            }
        }
        text.append("\n\n判定边界：这是本应用当前系统路由的入口响应测试。HTTP 403 可能来自地区限制、平台风控或机器人挑战；未登录测试不能保证账号和具体模型可用。");
        aiTestStatus.setText(text.toString());
    }

    private void showDetailDialog() {
        final EditText ip = new EditText(this); ip.setHint("一个公网 IP，例如 1.1.1.1"); ip.setSingleLine(true);
        IpParser.ParseReport current = IpParser.parse(input == null ? "" : input.getText().toString());
        if (current.ips.size() == 1) ip.setText(current.ips.get(0));
        new AlertDialog.Builder(this).setTitle("单 IP 详细调查").setMessage("会查询公开数据库，并只对目标 443/TCP 发起一次 TLS 握手以读取证书；拒绝私网/保留地址，不做端口扫描。")
                .setView(ip).setNegativeButton("取消", null).setPositiveButton("开始后台调查", (dialog, which) -> {
                    String value = ip.getText().toString().trim();
                    String normalized = IpParser.normalize(value);
                    if (normalized == null || !IpParser.isPublic(normalized)) { toast("请输入且只输入一个公网 IP"); return; }
                    requestNotificationPermission(); detailButton.setEnabled(false); realTestButton.setEnabled(false);
                    advancedStatus.setText("详细调查已交给系统前台服务，可切换应用或锁屏…");
                    Intent service = new Intent(this, AdvancedTestForegroundService.class).setAction(AdvancedTestForegroundService.ACTION_DETAIL);
                    service.putExtra(AdvancedTestForegroundService.EXTRA_IP, normalized); startForeground(service);
                }).show();
    }

    private void showRealTestDialog() {
        final LinearLayout form = column(); form.setPadding(dp(20), 0, dp(20), 0);
        final EditText controller = new EditText(this); controller.setHint("控制器，例如 http://127.0.0.1:9090"); controller.setSingleLine(true);
        controller.setText(prefs().getString("real_controller", "http://127.0.0.1:9090")); form.addView(controller, matchWrap());
        final EditText secret = new EditText(this); secret.setHint("控制器 Secret（不保存）"); secret.setSingleLine(true); secret.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD); form.addView(secret, matchWrap());
        final EditText node = new EditText(this); node.setHint("精确节点名（留空自动测前 20 个）"); node.setSingleLine(true); form.addView(node, matchWrap());
        final EditText targets = new EditText(this); targets.setHint("自定义 HTTPS 域名/网址，逗号或换行；内置 9 个 AI 对话网址"); targets.setMinLines(2); form.addView(targets, matchWrap());
        final CheckBox browser = checkbox("只测上述精确节点并打开真实对话页面（测试后不恢复节点）", false); form.addView(browser);
        new AlertDialog.Builder(this).setTitle("订阅真实测试")
                .setMessage("需要先在 Clash/Mihomo/Clash Mate 开启 Android 系统 VPN/TUN 和 External Controller。测试期间会影响该策略组的其他流量；订阅仍只用于解析和名称匹配。")
                .setView(form).setNegativeButton("取消", null).setPositiveButton("确认并后台测试", (dialog, which) -> {
                    String url = subscriptionInput.getText().toString().trim();
                    if (url.isEmpty()) { toast("请先在订阅区域填写或载入订阅链接"); return; }
                    if (browser.isChecked() && node.getText().toString().trim().isEmpty()) { toast("浏览器模式必须填写一个精确节点名"); return; }
                    prefs().edit().putString("real_controller", controller.getText().toString().trim()).apply();
                    requestNotificationPermission(); detailButton.setEnabled(false); realTestButton.setEnabled(false);
                    advancedStatus.setText("真实测试已交给系统前台服务；正在核验 VPN、匹配节点并逐项访问…");
                    Intent service = new Intent(this, AdvancedTestForegroundService.class).setAction(AdvancedTestForegroundService.ACTION_REAL);
                    service.putExtra(AdvancedTestForegroundService.EXTRA_URL, url);
                    service.putExtra(AdvancedTestForegroundService.EXTRA_CONTROLLER, controller.getText().toString().trim());
                    service.putExtra(AdvancedTestForegroundService.EXTRA_SECRET, secret.getText().toString());
                    service.putExtra(AdvancedTestForegroundService.EXTRA_NODE, node.getText().toString());
                    service.putExtra(AdvancedTestForegroundService.EXTRA_TARGETS, targets.getText().toString());
                    service.putExtra(AdvancedTestForegroundService.EXTRA_BROWSER, browser.isChecked()); startForeground(service);
                }).show();
    }

    private void startForeground(Intent service) {
        try { if (Build.VERSION.SDK_INT >= 26) startForegroundService(service); else startService(service); }
        catch (Exception failure) { detailButton.setEnabled(true); realTestButton.setEnabled(true); advancedStatus.setText("高级后台服务启动失败：" + safe(failure)); }
    }

    private void restoreAdvancedState() {
        if (advancedStatus == null) return;
        AdvancedReportStore.State state = AdvancedReportStore.load(this);
        detailButton.setEnabled(!state.running); realTestButton.setEnabled(!state.running);
        if (state.running) { advancedStatus.setText("高级模式正在系统前台服务中运行…"); return; }
        if (state.error != null && !state.error.isEmpty()) { advancedStatus.setText("高级模式失败：" + state.error); return; }
        if (state.report != null && !state.report.isEmpty()) {
            advancedStatus.setText(("detail".equals(state.kind) ? "详细调查" : "真实测试") + "已完成。点击此处查看完整报告。");
            advancedStatus.setOnClickListener(new View.OnClickListener() { @Override public void onClick(View v) {
                AdvancedReportStore.State latest = AdvancedReportStore.load(MainActivity.this);
                if (!latest.report.isEmpty()) showTextDialog("detail".equals(latest.kind) ? "单 IP 详细调查" : "订阅真实测试", latest.report);
            }});
        }
    }

    private void updateSummary(int now) {
        int high = 0, warning = 0, info = 0, failed = 0, local = 0;
        synchronized (results) {
            for (IpResult item : results) {
                if ("高风险".equals(item.status)) high++;
                if ("需注意".equals(item.status)) warning++;
                if ("信息可用".equals(item.status)) info++;
                if ("失败".equals(item.status)) failed++;
                if ("私网/保留".equals(item.status)) local++;
            }
        }
        summary.setText(scanLabel + " · 已完成 " + Math.min(now, total) + "/" + total + " · 高风险 " + high
                + " · 注意 " + warning + " · 仅信息 " + info + " · 失败 " + failed + (local > 0 ? " · 本地拦截 " + local : ""));
        progress.setProgress(total == 0 ? 0 : (int) (100L * Math.min(now, total) / total));
    }

    private void finishUi() {
        scanRunning = false;
        startButton.setEnabled(true); cancelButton.setEnabled(false); exportButton.setEnabled(!results.isEmpty());
        exitButton.setEnabled(true); subscriptionButton.setEnabled(true);
    }

    private void cancelScan() {
        Intent cancel = new Intent(this, ScanForegroundService.class).setAction(ScanForegroundService.ACTION_CANCEL_SCAN);
        try { startService(cancel); toast("已请求后台服务取消；进行中的 HTTPS 请求会在超时后结束"); }
        catch (Exception e) { toast("取消失败：" + safe(e)); }
    }

    private boolean isRunning() { return scanRunning; }

    private void clearAll() {
        input.setText(""); pendingOrigins.clear(); results.clear(); resultViews.clear(); resultContainer.removeAllViews();
        resultContainer.addView(emptyState); progress.setProgress(0); summary.setText("尚未开始"); exportButton.setEnabled(false);
    }

    private void prepareForBackgroundTask() {
        results.clear(); resultViews.clear(); resultContainer.removeAllViews(); pendingOrigins.clear();
        input.setText(""); total = 0; progress.setProgress(0); exportButton.setEnabled(false);
        startButton.setEnabled(false); cancelButton.setEnabled(true);
    }

    private void restoreScanState() {
        ScanStateStore.Snapshot state = ScanStateStore.load(this);
        if (state == null || state.results.isEmpty()) return;
        scanLabel = state.label; total = state.total; scanRunning = state.running;
        results.clear(); resultViews.clear(); resultContainer.removeAllViews();
        StringBuilder ips = new StringBuilder();
        for (IpResult result : state.results) {
            if (ips.length() > 0) ips.append('\n'); ips.append(result.ip);
            results.add(result); ResultViews views = addResultCard(result); resultViews.put(result.ip, views);
            if (!"等待".equals(result.status)) bind(views, result);
        }
        input.setText(ips.toString());
        startButton.setEnabled(!scanRunning); cancelButton.setEnabled(scanRunning);
        exitButton.setEnabled(!scanRunning); subscriptionButton.setEnabled(!scanRunning);
        exportButton.setEnabled(!state.results.isEmpty() && !scanRunning);
        updateSummary(state.completed);
    }

    private void requestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 733);
        }
    }

    private ResultViews addResultCard(IpResult result) {
        LinearLayout card = card();
        LinearLayout top = row(); top.setGravity(Gravity.CENTER_VERTICAL);
        TextView ip = label(result.ip, 17, INK, Typeface.BOLD); ip.setTextIsSelectable(true);
        TextView state = badge(result.status, MUTED);
        top.addView(ip, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1)); top.addView(state);
        TextView origin = detailLabel("来源：" + (result.origin.isEmpty() ? "手动输入" : result.origin));
        TextView score = detailLabel("等待查询");
        TextView flags = detailLabel("—");
        TextView location = detailLabel("—");
        TextView extra = detailLabel("—");
        TextView network = detailLabel("—");
        TextView ai = detailLabel("AI 平台：等待国家、ASN与风险证据");
        TextView registration = detailLabel("注册：等待 RDAP");
        TextView routing = detailLabel("路由：等待 RIPEstat");
        TextView timing = detailLabel("—");
        TextView sources = label("", 11, Color.rgb(108, 119, 140), Typeface.NORMAL);
        sources.setPadding(0, dp(8), 0, 0); sources.setTextIsSelectable(true);
        card.addView(top); card.addView(origin); card.addView(score); card.addView(flags); card.addView(location);
        card.addView(extra); card.addView(network); card.addView(ai); card.addView(registration); card.addView(routing); card.addView(timing); card.addView(sources);
        resultContainer.addView(card, spaced());
        return new ResultViews(card, state, score, flags, location, extra, network, ai, registration, routing, timing, sources);
    }

    private TextView detailLabel(String text) {
        TextView view = label(text, 13, MUTED, Typeface.NORMAL); view.setPadding(0, dp(5), 0, 0); view.setTextIsSelectable(true); return view;
    }

    private void bind(ResultViews v, IpResult r) {
        int color = statusColor(r.status);
        v.state.setText(r.status); v.state.setTextColor(color);
        v.state.setBackground(rounded(withAlpha(color, 28), Color.TRANSPARENT, 999, 0));
        v.score.setText(!r.riskEvaluated ? "风险：本次成功数据源未提供风险判定，不能据此称为低风险"
                : (r.riskScore == null ? "风险分：无数字评分（按来源查看标记）"
                : "最高风险分：" + r.riskScore + "/100 · " + r.riskSource + "（未跨源平均）"));
        v.score.setTextColor(color);
        v.flags.setText("风险标记：" + r.flagsText() + "\n信号共识：" + r.signalSummary);
        v.location.setText("地理归属：" + r.locationText());
        v.extra.setText("地理补充：" + r.detailText());
        v.network.setText("网络归属：" + r.networkText());
        v.ai.setText(AiPolicyEvaluator.evaluate(r));
        v.registration.setText("注册：" + (r.registration.isEmpty() ? "未返回" : r.registration));
        v.routing.setText("BGP/RPKI：" + (r.routing.isEmpty() ? "未返回" : r.routing));
        v.timing.setText("检测：成功源 " + r.successfulSources + " · 总耗时 " + r.durationMs() + " ms"
                + " · 可信度 " + r.confidence
                + (r.freshness.isEmpty() ? " · 上游未提供统一更新时间" : " · " + r.freshness));
        String detail = "逐来源证据：\n" + IpResult.join(r.sourceEvidence, "\n")
                + (r.sourceDetails.isEmpty() ? "" : "\n字段明细：\n" + IpResult.join(r.sourceDetails, "\n"))
                + (r.conflicts.isEmpty() ? "\n字段冲突：无" : "\n字段冲突（已保留多数结果）：\n" + IpResult.join(r.conflicts, "\n"));
        if (!r.errors.isEmpty()) detail += "\n错误/缺失：" + IpResult.join(r.errors, "；");
        v.sources.setText(detail); v.sources.setVisibility(View.VISIBLE);
    }

    private void applyResultFilter() {
        String query = resultSearch == null ? "" : resultSearch.getText().toString().trim().toLowerCase(Locale.ROOT);
        int visible = 0;
        synchronized (results) {
            for (IpResult result : results) {
                boolean status = "全部".equals(resultStatusFilter) || resultStatusFilter.equals(result.status)
                        || ("代理/VPN/机房".equals(resultStatusFilter) && (result.proxy || result.vpn || result.datacenter || result.tor));
                String haystack = (result.ip + " " + result.origin + " " + result.country + " " + result.countryCode
                        + " " + result.region + " " + result.city + " " + result.asn + " " + result.org).toLowerCase(Locale.ROOT);
                boolean show = status && (query.isEmpty() || haystack.contains(query));
                ResultViews views = resultViews.get(result.ip); if (views != null) views.root.setVisibility(show ? View.VISIBLE : View.GONE);
                if (show) visible++;
            }
        }
        toast("显示 " + visible + "/" + results.size() + " 条结果");
    }

    private void showResultFilterDialog(final Button button) {
        final String[] values = new String[]{"全部", "高风险", "需注意", "低风险", "信息可用", "失败", "私网/保留", "代理/VPN/机房"};
        new AlertDialog.Builder(this).setTitle("结果状态筛选").setItems(values, (dialog, which) -> {
            resultStatusFilter = values[which]; button.setText("状态：" + resultStatusFilter); applyResultFilter();
        }).show();
    }

    private void sortResultsByRisk() {
        synchronized (results) {
            Collections.sort(results, (one, two) -> {
                int a = severity(one), b = severity(two);
                if (a != b) return b - a;
                int ar = one.riskScore == null ? -1 : one.riskScore;
                int br = two.riskScore == null ? -1 : two.riskScore;
                return br - ar;
            });
        }
        rebuildResultCards(); applyResultFilter();
    }

    private int severity(IpResult value) {
        if ("高风险".equals(value.status)) return 6; if ("需注意".equals(value.status)) return 5;
        if ("失败".equals(value.status)) return 4; if ("信息可用".equals(value.status)) return 3;
        if ("低风险".equals(value.status)) return 2; return 1;
    }

    private void rebuildResultCards() {
        resultContainer.removeAllViews(); resultViews.clear();
        synchronized (results) {
            for (IpResult result : results) {
                ResultViews views = addResultCard(result); resultViews.put(result.ip, views);
                if (!"等待".equals(result.status)) bind(views, result);
            }
        }
    }

    private void showScanHistory() {
        List<ScanHistoryStore.Entry> history = ScanHistoryStore.list(this);
        if (history.isEmpty()) { toast("尚无已完成扫描历史"); return; }
        StringBuilder text = new StringBuilder();
        if (history.size() > 1) text.append(ScanHistoryStore.compare(history.get(0), history.get(1))).append("\n\n");
        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault());
        for (int i = 0; i < history.size(); i++) {
            ScanHistoryStore.Entry item = history.get(i);
            text.append(i + 1).append(". ").append(format.format(new Date(item.time))).append(" · ").append(item.label)
                    .append("\n   总数 ").append(item.total).append(" · 高风险 ").append(item.high)
                    .append(" · 注意 ").append(item.warning).append(" · 低风险 ").append(item.low)
                    .append(" · 仅信息 ").append(item.info).append(" · 失败 ").append(item.failed).append("\n");
        }
        text.append("\n最多保存最近 10 次轻量历史；不保存订阅原文或订阅凭证。比较基于相同 IP 的状态与风险分变化。");
        showTextDialog("扫描历史与最近对比", text.toString());
    }

    private void showSettings() {
        final SharedPreferences prefs = prefs();
        LinearLayout form = column(); form.setPadding(dp(20), dp(8), dp(20), 0);
        final CheckBox ipapi = checkbox("ipapi.is（归属/ASN/可选风险字段）", prefs.getBoolean("ipapi", true));
        final EditText ipapiKey = passwordField("ipapi.is Key（可空）", secretValue("ipapi_key"));
        final CheckBox proxy = checkbox("proxycheck.io（风险分、代理/VPN）", prefs.getBoolean("proxy", true));
        final EditText proxyKey = passwordField("proxycheck.io Key（可空）", secretValue("proxy_key"));
        final CheckBox geo = checkbox("GeoJS（备用位置/ASN）", prefs.getBoolean("geo", true));
        final CheckBox rdap = checkbox("RDAP（注册机构、网段、状态、事件）", prefs.getBoolean("rdap", true));
        final CheckBox ripe = checkbox("RIPEstat（BGP前缀、Origin ASN、RPKI）", prefs.getBoolean("ripe", true));
        final CheckBox ping0 = checkbox("Ping0 官方付费 API", prefs.getBoolean("ping0", false));
        final CheckBox useCache = checkbox("使用 15 分钟成功结果缓存（关闭即强制刷新）", prefs.getBoolean("use_cache", true));
        final EditText ping0Key = passwordField("Ping0 API Key", secretValue("ping0_key"));
        final EditText userAgent = new EditText(this);
        userAgent.setHint("订阅 User-Agent"); userAgent.setText(prefs.getString("subscription_ua", "Clash.Meta"));
        userAgent.setSingleLine(true); userAgent.setTextSize(13); userAgent.setPadding(dp(10), dp(8), dp(10), dp(8));
        TextView privacy = label("订阅链接和 API Key 使用 Android Keystore 加密保存；只在用户点击时识别出口。公网目标 IP 会逐个发送给启用的数据源。", 12, MUTED, Typeface.NORMAL);
        privacy.setPadding(0, dp(12), 0, 0);
        form.addView(ipapi); form.addView(ipapiKey, matchWrap()); form.addView(proxy); form.addView(proxyKey, matchWrap());
        form.addView(geo); form.addView(rdap); form.addView(ripe); form.addView(ping0); form.addView(ping0Key, matchWrap()); form.addView(useCache);
        form.addView(userAgent, matchWrap()); form.addView(privacy);
        final AlertDialog alert = new AlertDialog.Builder(this).setTitle("数据源与订阅设置").setView(form)
                .setNegativeButton("取消", null).setPositiveButton("保存", null).create();
        alert.setOnShowListener(dialog -> alert.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
            if (!ipapi.isChecked() && !proxy.isChecked() && !geo.isChecked() && !rdap.isChecked() && !ripe.isChecked() && !ping0.isChecked()) {
                toast("至少启用一个数据源"); return;
            }
            if (ping0.isChecked() && ping0Key.getText().toString().trim().isEmpty()) { toast("启用 Ping0 前请填写 Key"); return; }
            try {
                secretStore.put("ipapi_key", ipapiKey.getText().toString().trim());
                secretStore.put("proxy_key", proxyKey.getText().toString().trim());
                secretStore.put("ping0_key", ping0Key.getText().toString().trim());
            } catch (Exception e) { toast("密钥加密保存失败"); return; }
            prefs.edit().putBoolean("ipapi", ipapi.isChecked()).putBoolean("proxy", proxy.isChecked())
                    .putBoolean("geo", geo.isChecked()).putBoolean("rdap", rdap.isChecked()).putBoolean("ripe", ripe.isChecked())
                    .putBoolean("ping0", ping0.isChecked()).putBoolean("use_cache", useCache.isChecked()).putString("subscription_ua", userAgent.getText().toString().trim())
                    .remove("ipapi_key").remove("proxy_key").remove("ping0_key").apply();
            alert.dismiss();
        }));
        alert.show();
    }

    private String secretValue(String name) {
        String secure = secretStore.get(name); if (!secure.isEmpty()) return secure;
        return prefs().getString(name, "");
    }

    private void exportCsv() {
        if (results.isEmpty()) { toast("暂无结果"); return; }
        pendingCsv = CsvExporter.create(results);
        String stamp = new SimpleDateFormat("yyyyMMdd_HHmm", Locale.US).format(new Date());
        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT); intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("text/csv"); intent.putExtra(Intent.EXTRA_TITLE, "IP系统情报_" + stamp + ".csv");
        startActivityForResult(intent, EXPORT_REQUEST);
    }

    @Override protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != EXPORT_REQUEST || resultCode != RESULT_OK || data == null || pendingCsv == null) return;
        Uri uri = data.getData(); if (uri == null) return;
        try {
            OutputStream output = getContentResolver().openOutputStream(uri);
            if (output == null) throw new Exception("无法打开目标文件");
            output.write(pendingCsv.getBytes(StandardCharsets.UTF_8)); output.close(); toast("详细 CSV 已保存");
        } catch (Exception e) { toast("导出失败：" + safe(e)); }
        finally { pendingCsv = null; }
    }

    private void copy(IpResult from, IpResult to) {
        String origin = to.origin;
        to.status = from.status; to.riskScore = from.riskScore; to.riskSource = from.riskSource;
        to.country = from.country; to.countryCode = from.countryCode; to.region = from.region; to.city = from.city; to.asn = from.asn; to.org = from.org;
        to.networkType = from.networkType; to.coordinates = from.coordinates; to.timezone = from.timezone;
        to.registration = from.registration; to.routing = from.routing; to.freshness = from.freshness; to.confidence = from.confidence;
        to.signalSummary = from.signalSummary;
        to.vpn = from.vpn; to.proxy = from.proxy; to.tor = from.tor; to.datacenter = from.datacenter;
        to.abuser = from.abuser; to.mobile = from.mobile; to.riskEvaluated = from.riskEvaluated;
        to.nativeIp = from.nativeIp; to.successfulSources = from.successfulSources;
        to.countryAgreement = from.countryAgreement; to.asnAgreement = from.asnAgreement;
        to.startedAt = from.startedAt; to.finishedAt = from.finishedAt; to.origin = origin;
        to.sourceDetails.clear(); to.sourceDetails.addAll(from.sourceDetails);
        to.sourceEvidence.clear(); to.sourceEvidence.addAll(from.sourceEvidence);
        to.errors.clear(); to.errors.addAll(from.errors);
        to.conflicts.clear(); to.conflicts.addAll(from.conflicts);
        to.signalEvidence.clear(); to.signalEvidence.addAll(from.signalEvidence);
    }

    private boolean networkAvailable() {
        try {
            ConnectivityManager manager = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
            if (manager == null) return false; Network network = manager.getActiveNetwork(); if (network == null) return false;
            NetworkCapabilities caps = manager.getNetworkCapabilities(network);
            return caps != null && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET);
        } catch (Exception ignored) { return true; }
    }

    private String safe(Exception e) {
        String message = e.getMessage();
        if (message == null || message.trim().isEmpty()) return e.getClass().getSimpleName();
        return message.replaceAll("token=[^&\\s]+", "token=***").replaceAll("key=[^&\\s]+", "key=***");
    }

    private SharedPreferences prefs() { return getSharedPreferences("sources", MODE_PRIVATE); }
    private LinearLayout column() { LinearLayout v = new LinearLayout(this); v.setOrientation(LinearLayout.VERTICAL); return v; }
    private LinearLayout row() { LinearLayout v = new LinearLayout(this); v.setOrientation(LinearLayout.HORIZONTAL); return v; }
    private LinearLayout card() { LinearLayout v = column(); v.setPadding(dp(16), dp(15), dp(16), dp(15)); v.setBackground(rounded(Color.WHITE, Color.rgb(229, 233, 241), 15, 1)); return v; }
    private TextView label(String text, int sp, int color, int style) { TextView v = new TextView(this); v.setText(text); v.setTextSize(sp); v.setTextColor(color); v.setTypeface(Typeface.create("sans", style)); v.setLineSpacing(0, 1.08f); return v; }
    private TextView badge(String text, int color) { TextView v = label(text, 12, color, Typeface.BOLD); v.setPadding(dp(10), dp(5), dp(10), dp(5)); v.setBackground(rounded(withAlpha(color, 28), Color.TRANSPARENT, 999, 0)); return v; }
    private Button primaryButton(String text) { Button b = new Button(this); b.setText(text); b.setTextSize(13); b.setTextColor(Color.WHITE); b.setAllCaps(false); b.setBackgroundTintList(ColorStateList.valueOf(BLUE)); b.setMinHeight(dp(42)); return b; }
    private Button secondaryButton(String text) { Button b = new Button(this); b.setText(text); b.setTextSize(13); b.setTextColor(INK); b.setAllCaps(false); b.setBackgroundTintList(ColorStateList.valueOf(Color.WHITE)); b.setMinHeight(dp(42)); return b; }
    private CheckBox checkbox(String text, boolean checked) { CheckBox box = new CheckBox(this); box.setText(text); box.setTextSize(14); box.setTextColor(INK); box.setChecked(checked); box.setPadding(0, dp(3), 0, dp(3)); return box; }
    private EditText passwordField(String hint, String value) { EditText edit = new EditText(this); edit.setHint(hint); edit.setText(value); edit.setTextSize(13); edit.setSingleLine(true); edit.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD); edit.setPadding(dp(10), dp(8), dp(10), dp(8)); return edit; }
    private GradientDrawable rounded(int fill, int stroke, int radiusDp, int strokeDp) { GradientDrawable d = new GradientDrawable(); d.setColor(fill); d.setCornerRadius(dp(radiusDp)); if (strokeDp > 0) d.setStroke(dp(strokeDp), stroke); return d; }
    private LinearLayout.LayoutParams matchWrap() { return new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT); }
    private LinearLayout.LayoutParams spaced() { LinearLayout.LayoutParams p = matchWrap(); p.bottomMargin = dp(14); return p; }
    private LinearLayout.LayoutParams buttonParams() { LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, dp(44)); p.rightMargin = dp(8); return p; }
    private int dp(int value) { return Math.round(value * getResources().getDisplayMetrics().density); }
    private int withAlpha(int color, int alpha) { return Color.argb(alpha, Color.red(color), Color.green(color), Color.blue(color)); }
    private int statusColor(String status) { if ("高风险".equals(status) || "失败".equals(status)) return Color.rgb(206, 57, 69); if ("需注意".equals(status)) return Color.rgb(202, 126, 27); if ("低风险".equals(status)) return Color.rgb(24, 155, 103); if ("信息可用".equals(status)) return Color.rgb(61, 112, 180); if ("私网/保留".equals(status)) return Color.rgb(92, 99, 115); return BLUE; }
    private void toast(String message) { Toast.makeText(this, message, Toast.LENGTH_SHORT).show(); }

    private static final class ResultViews {
        final View root;
        final TextView state, score, flags, location, extra, network, ai, registration, routing, timing, sources;
        ResultViews(View root, TextView state, TextView score, TextView flags, TextView location, TextView extra, TextView network,
                    TextView ai, TextView registration, TextView routing, TextView timing, TextView sources) {
            this.root = root;
            this.state = state; this.score = score; this.flags = flags; this.location = location; this.extra = extra;
            this.network = network; this.ai = ai; this.registration = registration; this.routing = routing; this.timing = timing; this.sources = sources;
        }
    }
}
