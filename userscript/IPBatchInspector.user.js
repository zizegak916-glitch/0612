// ==UserScript==
// @name         IPBatchInspector 4
// @name:zh-CN   IPBatchInspector 4 - IP/订阅批量检测
// @namespace    https://github.com/zizegak916-glitch/0612
// @version      4.0.0
// @description  检测当前出口、批量查询公网 IP、只解析代理订阅并测试公开 AI 入口；永不连接订阅节点端口。
// @author       IPBatchInspector contributors
// @license      MIT
// @match        http://*/*
// @match        https://*/*
// @run-at       document-idle
// @grant        GM_xmlhttpRequest
// @grant        GM_registerMenuCommand
// @grant        GM_getValue
// @grant        GM_setValue
// @grant        GM_deleteValue
// @connect      *
// @downloadURL  https://raw.githubusercontent.com/zizegak916-glitch/0612/main/userscript/IPBatchInspector.user.js
// @updateURL    https://raw.githubusercontent.com/zizegak916-glitch/0612/main/userscript/IPBatchInspector.user.js
// ==/UserScript==

(function () {
  'use strict';

  const VERSION = '4.0.0';
  const MAX_BODY = 5 * 1024 * 1024;
  const MAX_NODES = 500;
  const MAX_PROVIDERS = 8;
  const STORAGE_KEY = 'ipbatch.encryptedSubscriptions.v1';
  const API_TIMEOUT = 12000;
  const SUPPORTED = new Set([
    'ss', 'ssr', 'vmess', 'vless', 'trojan', 'hysteria', 'hysteria2', 'hy2',
    'tuic', 'socks', 'socks4', 'socks5', 'http', 'https', 'anytls', 'juicity',
    'mieru', 'shadowtls', 'wireguard', 'wg', 'ssh', 'naive+https'
  ]);

  let panel;
  let output;
  let lastResult = null;

  function now() {
    return new Date().toISOString();
  }

  function request(options) {
    return new Promise((resolve, reject) => {
      const started = performance.now();
      GM_xmlhttpRequest({
        method: options.method || 'GET',
        url: options.url,
        headers: options.headers || {},
        data: options.data,
        timeout: options.timeout || API_TIMEOUT,
        anonymous: options.anonymous !== false,
        responseType: options.responseType || 'text',
        redirect: options.redirect || 'follow',
        onload: (response) => resolve({
          status: response.status,
          text: response.responseText || '',
          response: response.response,
          finalUrl: response.finalUrl || options.url,
          headers: response.responseHeaders || '',
          elapsedMs: Math.round(performance.now() - started)
        }),
        ontimeout: () => reject(new Error('请求超时')),
        onerror: (error) => reject(new Error(error && error.error ? error.error : '网络请求失败'))
      });
    });
  }

  function decodeBase64(value) {
    const normalized = value.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized + '='.repeat((4 - normalized.length % 4) % 4);
    const bytes = Uint8Array.from(atob(padded), (ch) => ch.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  }

  function stripQuotes(value) {
    const text = String(value || '').trim();
    if ((text.startsWith('"') && text.endsWith('"')) || (text.startsWith("'") && text.endsWith("'"))) {
      return text.slice(1, -1);
    }
    return text;
  }

  function isIPv4(value) {
    const parts = String(value).split('.');
    return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255);
  }

  function isIPv6(value) {
    const text = String(value).replace(/^\[|\]$/g, '');
    return text.includes(':') && /^[0-9a-f:.]+$/i.test(text);
  }

  function isPrivateHost(hostname) {
    const host = String(hostname || '').toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
    if (!host || host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal')) return true;
    if (isIPv4(host)) {
      const p = host.split('.').map(Number);
      return p[0] === 0 || p[0] === 10 || p[0] === 127 || p[0] >= 224 ||
        (p[0] === 169 && p[1] === 254) || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
        (p[0] === 192 && p[1] === 168) || (p[0] === 100 && p[1] >= 64 && p[1] <= 127) ||
        (p[0] === 192 && p[1] === 0 && p[2] === 0) || (p[0] === 192 && p[1] === 88 && p[2] === 99) ||
        (p[0] === 198 && (p[1] === 18 || p[1] === 19)) || p[0] >= 240 ||
        (p[0] === 192 && p[1] === 0 && p[2] === 2) || (p[0] === 198 && p[1] === 51 && p[2] === 100) ||
        (p[0] === 203 && p[1] === 0 && p[2] === 113);
    }
    if (isIPv6(host)) {
      return host === '::' || host === '::1' || /^f[cd]/i.test(host) || /^fe[89ab]/i.test(host) || /^2001:db8:/i.test(host);
    }
    return false;
  }

  async function resolveHost(hostname) {
    const host = String(hostname || '').replace(/^\[|\]$/g, '');
    if (isIPv4(host) || isIPv6(host)) return [host];
    const answers = [];
    for (const type of ['A', 'AAAA']) {
      try {
        const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=${type}`;
        const response = await request({ url, headers: { Accept: 'application/dns-json' } });
        if (response.status !== 200) continue;
        const body = JSON.parse(response.text);
        for (const answer of body.Answer || []) {
          if ((answer.type === 1 || answer.type === 28) && (isIPv4(answer.data) || isIPv6(answer.data))) answers.push(answer.data);
        }
      } catch (_) {
        // Both record types are attempted; individual DNS failures remain visible through an empty result.
      }
    }
    return [...new Set(answers)];
  }

  async function validateSubscriptionUrl(raw, allowPrivate) {
    let url;
    try {
      url = new URL(raw);
    } catch (_) {
      throw new Error('订阅地址不是有效 URL');
    }
    if (!['http:', 'https:'].includes(url.protocol)) throw new Error('订阅只允许 HTTP(S)');
    if (url.username || url.password) throw new Error('拒绝 URL userinfo');
    const literalPrivate = isPrivateHost(url.hostname);
    if (literalPrivate && !allowPrivate) throw new Error('已拒绝本机、私网、保留或文档地址；如确为自建内网订阅需显式勾选');
    if (url.protocol === 'http:' && !literalPrivate) throw new Error('公网订阅必须使用 HTTPS');
    if (!literalPrivate) {
      const addresses = await resolveHost(url.hostname);
      if (!addresses.length) throw new Error('DoH 无法解析订阅域名，已停止下载');
      if (addresses.some(isPrivateHost)) throw new Error('订阅域名解析包含私网/保留地址，已阻止混合 DNS');
    }
    url.ipbatchRaw = raw;
    return url;
  }

  function extractSubscriptionUrl(value) {
    const wrappers = [
      /^sn:\/\/subscription/i,
      /^clash:\/\/install-config/i,
      /^stash:\/\/install-config/i,
      /^sing-box:\/\/import-remote-profile/i,
      /^surge:\/\/\/install-config/i,
      /^loon:\/\/import/i
    ];
    if (!wrappers.some((pattern) => pattern.test(value))) return value;
    const query = value.includes('?') ? value.slice(value.indexOf('?') + 1) : '';
    const params = new URLSearchParams(query);
    for (const key of ['url', 'target', 'subscription', 'remote-url']) {
      const candidate = params.get(key);
      if (candidate && /^https?:\/\//i.test(candidate)) return candidate.trim();
    }
    throw new Error('导入链接中没有显式 HTTP(S) 订阅地址');
  }

  function alternateFslUrl(value) {
    if (/([?&](?:format|target)=)fsl64(?=&|$)/i.test(value)) {
      return value.replace(/([?&](?:format|target)=)fsl64(?=&|$)/i, '$1fslyaml');
    }
    if (/([?&](?:format|target)=)fslyaml(?=&|$)/i.test(value)) {
      return value.replace(/([?&](?:format|target)=)fslyaml(?=&|$)/i, '$1fsl64');
    }
    return null;
  }

  function node(protocol, host, port, name, source, chain) {
    const cleanHost = stripQuotes(host).replace(/^\[|\]$/g, '').trim();
    const cleanPort = Number(String(port || '').replace(/[^0-9]/g, ''));
    if (!cleanHost || cleanHost.length > 253 || !cleanPort || cleanPort > 65535) return null;
    return {
      protocol: String(protocol || 'unknown').toLowerCase(),
      host: cleanHost,
      port: cleanPort,
      name: String(name || '').slice(0, 120),
      source: String(source || 'subscription'),
      chain: chain ? String(chain).slice(0, 120) : null
    };
  }

  function parseUri(line, source) {
    const raw = line.trim().replace(/^[-*]\s+/, '');
    const match = raw.match(/^([a-z][a-z0-9+.-]*):\/\//i);
    if (!match || !SUPPORTED.has(match[1].toLowerCase())) return null;
    const protocol = match[1].toLowerCase();
    try {
      if (protocol === 'vmess') {
        const data = JSON.parse(decodeBase64(raw.slice(raw.indexOf('://') + 3).split('#')[0]));
        return node('vmess', data.add || data.host, data.port, data.ps, source, data['dialer-proxy']);
      }
      if (protocol === 'ssr') {
        const decoded = decodeBase64(raw.slice(6).split('#')[0]);
        const base = decoded.split('/?')[0];
        const parts = base.split(':');
        return node('ssr', parts.slice(0, -5).join(':'), parts[parts.length - 5], '', source, null);
      }
      if (protocol === 'ss') {
        let rest = raw.slice(5);
        const hash = rest.indexOf('#');
        const name = hash >= 0 ? decodeURIComponent(rest.slice(hash + 1)) : '';
        if (hash >= 0) rest = rest.slice(0, hash);
        const queryAt = rest.indexOf('?');
        const query = queryAt >= 0 ? rest.slice(queryAt) : '';
        if (queryAt >= 0) rest = rest.slice(0, queryAt);
        if (!rest.includes('@')) rest = decodeBase64(rest);
        const parsed = new URL(`ss://${rest}${query}`);
        return node('ss', parsed.hostname, parsed.port, name, source, parsed.searchParams.get('dialer-proxy'));
      }
      const parsed = new URL(raw);
      const name = parsed.hash ? decodeURIComponent(parsed.hash.slice(1)) : parsed.searchParams.get('remarks') || '';
      return node(protocol, parsed.hostname, parsed.port || (protocol === 'https' ? 443 : 80), name, source, parsed.searchParams.get('dialer-proxy'));
    } catch (_) {
      return null;
    }
  }

  function parseYaml(text, source) {
    const nodes = [];
    const lines = text.split(/\r?\n/);
    let inProxies = false;
    let current = null;

    function flush() {
      if (!current) return;
      const item = node(current.type, current.server, current.port, current.name, source, current['dialer-proxy']);
      if (item) nodes.push(item);
      current = null;
    }

    for (const line of lines) {
      if (/^proxies\s*:/i.test(line)) {
        flush();
        inProxies = true;
        continue;
      }
      if (inProxies && /^\S[^:]*:\s*/.test(line) && !/^\s*-/.test(line)) {
        flush();
        inProxies = false;
      }
      if (!inProxies) continue;
      const inline = line.match(/^\s*-\s*\{(.+)\}\s*$/);
      if (inline) {
        flush();
        const fields = {};
        for (const pair of inline[1].split(/,(?=(?:[^"']|"[^"]*"|'[^']*')*$)/)) {
          const index = pair.indexOf(':');
          if (index > 0) fields[pair.slice(0, index).trim()] = stripQuotes(pair.slice(index + 1));
        }
        const item = node(fields.type, fields.server, fields.port, fields.name, source, fields['dialer-proxy']);
        if (item) nodes.push(item);
        continue;
      }
      const first = line.match(/^\s*-\s*name\s*:\s*(.+)$/i);
      if (first) {
        flush();
        current = { name: stripQuotes(first[1]) };
        continue;
      }
      const field = line.match(/^\s+(name|type|server|port|dialer-proxy)\s*:\s*(.+)$/i);
      if (field && current) current[field[1].toLowerCase()] = stripQuotes(field[2]);
    }
    flush();
    return nodes;
  }

  function providerUrls(text) {
    const found = [];
    const lines = text.split(/\r?\n/);
    let inProviders = false;
    for (const line of lines) {
      if (/^proxy-providers\s*:/i.test(line)) {
        inProviders = true;
        continue;
      }
      if (inProviders && /^\S[^:]*:\s*/.test(line)) break;
      if (!inProviders) continue;
      const match = line.match(/^\s+url\s*:\s*["']?(https?:\/\/[^\s"']+)/i);
      if (match) found.push(match[1]);
    }
    return [...new Set(found)].slice(0, MAX_PROVIDERS);
  }

  function parseContent(content, source) {
    let text = String(content || '').replace(/^\uFEFF/, '').trim();
    if (!text) return { nodes: [], providers: [] };
    if (!/:\/\//.test(text) && /^[A-Za-z0-9_+/=\r\n-]+$/.test(text)) {
      try {
        const decoded = decodeBase64(text);
        if (/:\/\//.test(decoded) || /proxies\s*:/i.test(decoded)) text = decoded;
      } catch (_) {
        // Not a whole-document Base64 subscription; continue with original text.
      }
    }
    const nodes = parseYaml(text, source);
    for (const line of text.split(/[\r\n]+/)) {
      const item = parseUri(line, source);
      if (item) nodes.push(item);
    }
    const unique = [];
    const seen = new Set();
    for (const item of nodes) {
      const key = `${item.protocol}|${item.host.toLowerCase()}|${item.port}`;
      if (!seen.has(key) && unique.length < MAX_NODES) {
        seen.add(key);
        unique.push(item);
      }
    }
    return { nodes: unique, providers: providerUrls(text) };
  }

  async function downloadSubscription(rawUrl, allowPrivate, source) {
    const normalized = extractSubscriptionUrl(rawUrl);
    const initial = await validateSubscriptionUrl(normalized, allowPrivate);
    let approved = initial;
    let response;
    for (let redirects = 0; redirects <= 4; redirects += 1) {
      response = await request({ url: approved.ipbatchRaw || approved.href, timeout: 20000, redirect: 'manual' });
      if (response.status < 300 || response.status >= 400) break;
      const location = response.headers.match(/^location:\s*(.+)$/im);
      if (!location) throw new Error(`订阅返回 HTTP ${response.status}，但没有可审计的 Location`);
      approved = await validateSubscriptionUrl(new URL(location[1].trim(), approved).href, allowPrivate);
      if (redirects === 4) throw new Error('订阅重定向超过 4 次');
    }
    if (response.status < 200 || response.status >= 300) throw new Error(`订阅 HTTP ${response.status}`);
    if (response.text.length > MAX_BODY) throw new Error('订阅正文超过 5 MiB');
    const finalApproved = await validateSubscriptionUrl(response.finalUrl, allowPrivate);
    if (finalApproved.origin !== approved.origin) {
      throw new Error('当前油猴实现未遵守手动重定向，跨站最终响应已丢弃；请升级 Tampermonkey 或直接使用最终 HTTPS 地址');
    }
    const parsed = parseContent(response.text, source || approved.hostname);
    return { url: approved.ipbatchRaw || approved.href, elapsedMs: response.elapsedMs, ...parsed };
  }

  async function inspectIp(ip) {
    const encoded = encodeURIComponent(ip);
    const definitions = [
      ['ipapi', `https://api.ipapi.is/?q=${encoded}`],
      ['proxycheck', `https://proxycheck.io/v2/${encoded}?vpn=1&asn=1&risk=1`],
      ['geojs', `https://get.geojs.io/v1/ip/geo/${encoded}.json`],
      ['rdap', `https://rdap.org/ip/${encoded}`],
      ['ripestat', `https://stat.ripe.net/data/routing-status/data.json?resource=${encoded}`]
    ];
    const evidence = await Promise.all(definitions.map(async ([source, url]) => {
      const queriedAt = now();
      try {
        const response = await request({ url });
        let data = null;
        try { data = JSON.parse(response.text); } catch (_) { data = { excerpt: response.text.slice(0, 240) }; }
        return { source, queriedAt, elapsedMs: response.elapsedMs, status: response.status, ok: response.status >= 200 && response.status < 300, data };
      } catch (error) {
        return { source, queriedAt, ok: false, error: error.message };
      }
    }));
    return { ip, queriedAt: now(), evidence };
  }

  async function mapLimit(items, limit, fn, progress) {
    const results = new Array(items.length);
    let cursor = 0;
    let finished = 0;
    async function worker() {
      while (true) {
        const index = cursor++;
        if (index >= items.length) return;
        results[index] = await fn(items[index], index);
        finished += 1;
        if (progress) progress(finished, items.length);
      }
    }
    await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
    return results;
  }

  function extractIps(text) {
    const candidates = String(text || '').match(/(?:\d{1,3}\.){3}\d{1,3}|(?:[0-9a-f]{0,4}:){2,}[0-9a-f:.]{0,39}/gi) || [];
    return [...new Set(candidates.filter((ip) => (isIPv4(ip) || isIPv6(ip)) && !isPrivateHost(ip)))].slice(0, MAX_NODES);
  }

  async function currentExit() {
    const attempts = [
      'https://api64.ipify.org?format=json',
      'https://api.ipify.org?format=json',
      'https://get.geojs.io/v1/ip.json'
    ];
    const errors = [];
    for (const url of attempts) {
      try {
        const response = await request({ url });
        const data = JSON.parse(response.text);
        const ip = data.ip;
        if (ip && !isPrivateHost(ip)) return { route: '当前浏览器/扩展所用系统路由', discoveredAt: now(), discoveryUrl: url, details: await inspectIp(ip) };
      } catch (error) {
        errors.push(`${url}: ${error.message}`);
      }
    }
    throw new Error(`出口 IP 检测失败：${errors.join('; ')}`);
  }

  async function inspectSubscription(url, allowPrivate, enrich) {
    const main = await downloadSubscription(url, allowPrivate, 'main');
    if (!main.nodes.length) {
      const alternate = alternateFslUrl(main.url);
      if (alternate) {
        const fallback = await downloadSubscription(alternate, allowPrivate, 'format fallback');
        main.nodes.push(...fallback.nodes);
        main.providers.push(...fallback.providers);
        main.formatFallback = alternate;
      }
    }
    const providerReports = [];
    for (const providerUrl of [...new Set(main.providers)].slice(0, MAX_PROVIDERS)) {
      try {
        const report = await downloadSubscription(providerUrl, allowPrivate, 'proxy-provider');
        main.nodes.push(...report.nodes);
        providerReports.push({ host: new URL(providerUrl).hostname, ok: true, nodes: report.nodes.length });
      } catch (error) {
        providerReports.push({ host: (() => { try { return new URL(providerUrl).hostname; } catch (_) { return 'invalid'; } })(), ok: false, error: error.message });
      }
    }
    const deduped = [];
    const seen = new Set();
    for (const item of main.nodes) {
      const key = `${item.protocol}|${item.host.toLowerCase()}|${item.port}`;
      if (!seen.has(key) && deduped.length < MAX_NODES) {
        seen.add(key);
        deduped.push(item);
      }
    }
    setStatus(`正在解析节点域名 0/${deduped.length}`);
    const resolved = await mapLimit(deduped, 4, async (item) => {
      const addresses = await resolveHost(item.host);
      return {
        ...item,
        addresses: addresses.filter((ip) => !isPrivateHost(ip)),
        rejectedAddresses: addresses.filter(isPrivateHost)
      };
    }, (done, total) => setStatus(`正在解析节点域名 ${done}/${total}（从未连接节点端口）`));
    const ips = [...new Set(resolved.flatMap((item) => item.addresses))];
    let intelligence = [];
    if (enrich && ips.length) {
      const targets = ips.slice(0, 30);
      intelligence = await mapLimit(targets, 3, inspectIp, (done, total) => setStatus(`正在查询 IP 情报 ${done}/${total}`));
    }
    return {
      kind: 'subscription',
      checkedAt: now(),
      subscription: { scheme: new URL(main.url).protocol, host: new URL(main.url).hostname, elapsedMs: main.elapsedMs },
      formats: [...new Set(deduped.map((item) => item.protocol))].sort(),
      counts: { nodes: deduped.length, resolvedPublicIps: ips.length, providers: providerReports.length, enrichedIps: intelligence.length },
      providers: providerReports,
      nodes: resolved,
      intelligence,
      formatFallback: main.formatFallback || null,
      networkBoundary: '只下载订阅文档、DoH 解析节点主机名并查询公网 IP 情报；节点端口只作为元数据，从未连接',
      userscriptLimitation: '现代 Tampermonkey 使用手动重定向逐跳审计；若扩展不支持该选项，跨站最终响应会被丢弃，但原生客户端仍具有更强的预连接地址固定保证'
    };
  }

  async function testAiEntrances() {
    const targets = [
      ['ChatGPT Web', 'https://chatgpt.com/'],
      ['OpenAI API', 'https://api.openai.com/v1/models'],
      ['Claude Web', 'https://claude.ai/'],
      ['Anthropic API', 'https://api.anthropic.com/v1/models'],
      ['Gemini Web', 'https://gemini.google.com/'],
      ['Google Generative Language API', 'https://generativelanguage.googleapis.com/v1beta/models']
    ];
    const results = await mapLimit(targets, 3, async ([name, url]) => {
      const queriedAt = now();
      try {
        const response = await request({ url, anonymous: true });
        return {
          name, url, queriedAt, status: response.status, elapsedMs: response.elapsedMs,
          reachable: response.status > 0 && response.status < 500,
          interpretation: [400, 401, 403].includes(response.status) ? '入口有 HTTP 响应；不代表账号、模型或地区可用' : '仅表示公开入口响应状态'
        };
      } catch (error) {
        return { name, url, queriedAt, reachable: false, error: error.message };
      }
    }, (done, total) => setStatus(`AI 公开入口直测 ${done}/${total}`));
    return { kind: 'ai-entrance', checkedAt: now(), route: '当前浏览器/扩展所用系统路由', credentialsSent: false, results };
  }

  function bytesToBase64(bytes) {
    let binary = '';
    bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
    return btoa(binary);
  }

  function base64ToBytes(value) {
    return Uint8Array.from(atob(value), (ch) => ch.charCodeAt(0));
  }

  async function deriveKey(passphrase, salt) {
    const material = await crypto.subtle.importKey('raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 210000 }, material,
      { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );
  }

  async function encryptSecret(value, passphrase) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(passphrase, salt);
    const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(value));
    return { salt: bytesToBase64(salt), iv: bytesToBase64(iv), cipher: bytesToBase64(new Uint8Array(cipher)) };
  }

  async function decryptSecret(record, passphrase) {
    const salt = base64ToBytes(record.salt);
    const iv = base64ToBytes(record.iv);
    const key = await deriveKey(passphrase, salt);
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, base64ToBytes(record.cipher));
    return new TextDecoder().decode(plain);
  }

  async function savedRecords() {
    return await Promise.resolve(GM_getValue(STORAGE_KEY, []));
  }

  async function saveCurrentSubscription() {
    const urlInput = panel.querySelector('[data-field="subscription"]');
    const rawUrl = urlInput.value.trim();
    if (!rawUrl) throw new Error('先输入订阅地址');
    const normalized = extractSubscriptionUrl(rawUrl);
    const parsed = new URL(normalized);
    const name = prompt('保存名称（列表只显示名称和主机，不显示 Token）', parsed.hostname);
    if (!name) return;
    const passphrase = prompt('设置加密口令（至少 8 位；口令不会保存，忘记后无法恢复）');
    if (!passphrase || passphrase.length < 8) throw new Error('加密口令至少 8 位');
    const encrypted = await encryptSecret(rawUrl, passphrase);
    const records = await savedRecords();
    const next = records.filter((record) => record.name !== name).slice(-49);
    next.push({ name: name.slice(0, 80), host: parsed.hostname, savedAt: now(), encrypted });
    await Promise.resolve(GM_setValue(STORAGE_KEY, next));
    setStatus(`已加密保存“${name}”；口令未保存`);
  }

  async function loadSavedSubscription() {
    const records = await savedRecords();
    if (!records.length) throw new Error('没有已保存订阅');
    const selection = prompt(`输入序号加载：\n${records.map((record, index) => `${index + 1}. ${record.name} — ${record.host}`).join('\n')}`);
    const index = Number(selection) - 1;
    if (!Number.isInteger(index) || !records[index]) return;
    const passphrase = prompt(`输入“${records[index].name}”的加密口令`);
    if (!passphrase) return;
    try {
      const url = await decryptSecret(records[index].encrypted, passphrase);
      panel.querySelector('[data-field="subscription"]').value = url;
      setStatus(`已解密载入“${records[index].name}”`);
    } catch (_) {
      throw new Error('口令错误或密文已损坏');
    }
  }

  function setStatus(message) {
    if (!panel) return;
    panel.querySelector('[data-role="status"]').textContent = message;
  }

  function renderResult(result) {
    lastResult = result;
    output.textContent = JSON.stringify(result, null, 2);
    setStatus(`完成 · ${now()}`);
  }

  async function run(label, task) {
    setStatus(label);
    output.textContent = '执行中…';
    panel.querySelectorAll('button').forEach((button) => { button.disabled = true; });
    try {
      renderResult(await task());
    } catch (error) {
      const failure = { ok: false, checkedAt: now(), error: error.message || String(error) };
      renderResult(failure);
    } finally {
      panel.querySelectorAll('button').forEach((button) => { button.disabled = false; });
    }
  }

  function downloadResult() {
    if (!lastResult) return;
    const blob = new Blob([JSON.stringify(lastResult, null, 2)], { type: 'application/json;charset=utf-8' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = `ipbatch-${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
    link.click();
    setTimeout(() => URL.revokeObjectURL(link.href), 1000);
  }

  function buildPanel() {
    if (panel) {
      panel.hidden = false;
      return;
    }
    const host = document.createElement('div');
    host.id = 'ipbatch-inspector-host';
    document.documentElement.appendChild(host);
    const shadow = host.attachShadow({ mode: 'closed' });
    const style = document.createElement('style');
    style.textContent = `
      :host{all:initial} *{box-sizing:border-box} .panel{position:fixed;z-index:2147483647;right:18px;bottom:18px;width:min(720px,calc(100vw - 36px));max-height:calc(100vh - 36px);overflow:auto;background:#101722;color:#e8eef7;border:1px solid #39506d;border-radius:14px;box-shadow:0 18px 55px #0009;font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;padding:16px}.head{display:flex;gap:12px;align-items:center}.head h2{font-size:18px;margin:0;flex:1}.badge{font-size:11px;color:#91b7e6}.close{width:auto!important;background:#253449!important}.notice{background:#172538;border-left:3px solid #4ca6ff;padding:9px 11px;margin:12px 0;color:#d5e8ff}.grid{display:grid;grid-template-columns:1fr auto;gap:8px}.row{display:flex;gap:8px;flex-wrap:wrap;margin:9px 0}input[type=text],textarea{width:100%;background:#0b111a;color:#fff;border:1px solid #38516d;border-radius:8px;padding:9px}textarea{min-height:82px;resize:vertical}button{border:0;border-radius:8px;padding:9px 12px;background:#1976d2;color:white;font-weight:650;cursor:pointer}button.secondary{background:#334961}button:disabled{opacity:.5;cursor:wait}label{display:flex;gap:6px;align-items:center;color:#c9d8e8}.status{color:#91b7e6;margin:7px 0}.out{white-space:pre-wrap;word-break:break-word;background:#070b10;color:#cfe2f6;border:1px solid #26384d;border-radius:8px;padding:12px;min-height:180px;max-height:42vh;overflow:auto;font:12px/1.45 ui-monospace,SFMono-Regular,Consolas,monospace}@media(max-width:560px){.panel{right:8px;bottom:8px;width:calc(100vw - 16px);max-height:calc(100vh - 16px)}.grid{grid-template-columns:1fr}}
    `;
    panel = document.createElement('section');
    panel.className = 'panel';
    panel.innerHTML = `
      <div class="head"><h2>IPBatchInspector</h2><span class="badge">v${VERSION} · 油猴版</span><button class="close" data-action="close">关闭</button></div>
      <div class="notice">订阅只下载/解析、DoH 解析主机名并查询公网 IP 情报；绝不连接节点端口，也不提供代理、隧道或绕过。油猴脚本受浏览器标签页生命周期限制，不是系统后台服务。</div>
      <div class="row"><button data-action="exit">检测当前出口</button><button data-action="ai">AI 公开入口直测</button></div>
      <textarea data-field="ips" placeholder="粘贴公网 IPv4/IPv6；自动去重，最多 500 个"></textarea>
      <div class="row"><button data-action="scan">批量 IP 情报</button></div>
      <div class="grid"><input type="text" data-field="subscription" autocomplete="off" spellcheck="false" placeholder="HTTPS 订阅、sn://subscription…"><button data-action="subscription">只解析订阅</button></div>
      <div class="row"><label><input type="checkbox" data-field="allow-private">显式允许本机/私网订阅</label><label><input type="checkbox" data-field="enrich" checked>查询前 30 个节点 IP 的五源情报</label></div>
      <div class="row"><button class="secondary" data-action="save">口令加密保存</button><button class="secondary" data-action="load">载入已保存</button><button class="secondary" data-action="export">导出 JSON</button></div>
      <div class="status" data-role="status">就绪 · 当前网页不会自动发起检测</div><pre class="out" data-role="output">权限说明：@connect * 仅用于访问用户输入的订阅域名；固定情报源和 DoH 也走 GM 请求。安装前可直接审查本文件全部源码。</pre>
    `;
    shadow.append(style, panel);
    output = panel.querySelector('[data-role="output"]');
    panel.addEventListener('click', (event) => {
      const button = event.target.closest('button[data-action]');
      if (!button) return;
      const action = button.dataset.action;
      if (action === 'close') panel.hidden = true;
      if (action === 'exit') run('正在检测当前出口…', currentExit);
      if (action === 'ai') run('正在直测 AI 公开入口…', testAiEntrances);
      if (action === 'scan') run('正在批量查询 IP 情报…', async () => {
        const ips = extractIps(panel.querySelector('[data-field="ips"]').value);
        if (!ips.length) throw new Error('没有可查询的公网 IP');
        const results = await mapLimit(ips, 3, inspectIp, (done, total) => setStatus(`批量 IP 情报 ${done}/${total}`));
        return { kind: 'batch-ip', checkedAt: now(), count: results.length, results };
      });
      if (action === 'subscription') run('正在安全下载并解析订阅…', () => {
        const url = panel.querySelector('[data-field="subscription"]').value.trim();
        if (!url) throw new Error('请输入订阅地址');
        return inspectSubscription(url, panel.querySelector('[data-field="allow-private"]').checked, panel.querySelector('[data-field="enrich"]').checked);
      });
      if (action === 'save') run('正在加密保存…', async () => { await saveCurrentSubscription(); return { ok: true, savedAt: now(), plaintextStored: false }; });
      if (action === 'load') run('正在载入加密订阅…', async () => { await loadSavedSubscription(); return { ok: true, loadedAt: now() }; });
      if (action === 'export') downloadResult();
    });
  }

  GM_registerMenuCommand('打开 IPBatchInspector', buildPanel);
})();
