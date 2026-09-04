// ==UserScript==
// @name         IPBatchInspector 5
// @name:zh-CN   IPBatchInspector 5 - IP/订阅/真实路由检测
// @namespace    https://github.com/zizegak916-glitch/0612
// @version      5.0.0
// @description  批量 IP 情报、单 IP 详细调查、只解析订阅，以及通过本机 Mihomo/Clash 系统 VPN 真实测试 AI 对话网址。
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

  const VERSION = '5.0.0';
  const MAX_BODY = 5 * 1024 * 1024;
  const MAX_NODES = 500;
  const MAX_PROVIDERS = 8;
  const STORAGE_KEY = 'ipbatch.encryptedSubscriptions.v1';
  const EVIDENCE_CACHE_KEY = 'ipbatch.providerEvidence.v1';
  const EVIDENCE_CACHE_TTL = 15 * 60 * 1000;
  const API_TIMEOUT = 12000;
  const SUPPORTED = new Set([
    'ss', 'ssr', 'vmess', 'vless', 'trojan', 'hysteria', 'hysteria2', 'hy2',
    'tuic', 'socks', 'socks4', 'socks5', 'http', 'https', 'anytls', 'juicity',
    'mieru', 'shadowtls', 'wireguard', 'wg', 'ssh', 'naive+https'
  ]);

  let panel;
  let output;
  let lastResult = null;
  let nextRdapStart = 0;

  function now() {
    return new Date().toISOString();
  }

  async function throttleRdap() {
    const scheduled = Math.max(Date.now(), nextRdapStart);
    nextRdapStart = scheduled + 1050;
    const wait = scheduled - Date.now();
    if (wait > 0) await new Promise((resolve) => setTimeout(resolve, wait));
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

  function canonicalIp(value) {
    const text = String(value || '').replace(/^\[|\]$/g, '');
    if (isIPv4(text)) return text.split('.').map(Number).join('.');
    if (isIPv6(text)) {
      try { return new URL(`http://[${text}]/`).hostname.toLowerCase().replace(/^\[|\]$/g, ''); }
      catch (_) { return text.toLowerCase(); }
    }
    return '';
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
    const batches = await Promise.all(['A', 'AAAA'].map(async (type) => {
      try {
        const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=${type}`;
        const response = await request({ url, headers: { Accept: 'application/dns-json' } });
        if (response.status !== 200) return [];
        const body = JSON.parse(response.text);
        const answers = [];
        for (const answer of body.Answer || []) {
          if ((answer.type === 1 || answer.type === 28) && (isIPv4(answer.data) || isIPv6(answer.data))) answers.push(answer.data);
        }
        return answers;
      } catch (_) {
        return [];
      }
    }));
    return [...new Set(batches.flat())];
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

  function providerFields(source, ip, data) {
    const fields = {};
    if (source === 'ipapi') {
      if (data.error) throw new Error(data.message || 'ipapi 拒绝查询');
      if (data.ip && canonicalIp(data.ip) !== canonicalIp(ip)) throw new Error('ipapi 回显了不同目标 IP');
      const location = data.location || data;
      const asn = typeof data.asn === 'object' ? data.asn : {};
      Object.assign(fields, {
        country: location.country, country_code: location.country_code || location.countryCode,
        region: location.state || location.region, city: location.city,
        asn: asn.asn || data.asn, organization: asn.org || asn.name
      });
      for (const key of ['is_proxy', 'is_vpn', 'is_tor', 'is_datacenter', 'is_abuser']) {
        if (Object.prototype.hasOwnProperty.call(data, key)) fields[key.slice(3)] = Boolean(data[key]);
      }
    } else if (source === 'proxycheck') {
      if (String(data.status || '').toLowerCase() !== 'ok') throw new Error(data.message || 'proxycheck 状态异常');
      const targetKey = Object.keys(data).find((key) => canonicalIp(key) && canonicalIp(key) === canonicalIp(ip));
      const item = targetKey ? data[targetKey] : null;
      if (!item || typeof item !== 'object') throw new Error('proxycheck 未返回目标 IP');
      const type = String(item.type || '');
      Object.assign(fields, {
        country: item.country, country_code: item.isocode || item.country_code,
        region: item.region, city: item.city, asn: item.asn,
        organization: item.organisation || item.provider, proxy: String(item.proxy).toLowerCase() === 'yes',
        vpn: type.toLowerCase().includes('vpn'), tor: type.toLowerCase().includes('tor'),
        risk: item.risk, last_seen: item.last_seen || item['last seen']
      });
    } else if (source === 'geojs') {
      if (data.ip && canonicalIp(data.ip) !== canonicalIp(ip)) throw new Error('GeoJS 回显了不同目标 IP');
      Object.assign(fields, {
        country: data.country, country_code: data.country_code, region: data.region, city: data.city,
        asn: data.asn, organization: data.organization_name || data.organization
      });
    } else if (source === 'rdap') {
      Object.assign(fields, {
        start_address: data.startAddress, end_address: data.endAddress,
        registration_name: data.name || data.handle, registration_country: data.country,
        registration_type: data.type, registration_status: data.status
      });
    } else {
      if (!data.data || typeof data.data !== 'object') throw new Error('RIPEstat 缺少 data');
      const last = data.data.last_seen || {};
      Object.assign(fields, {
        prefix: last.prefix, origin_asn: last.origin ? `AS${String(last.origin).replace(/\D/g, '')}` : '',
        last_seen: last.time, announced: Boolean(data.data.last_seen)
      });
    }
    return Object.fromEntries(Object.entries(fields).filter(([, value]) => value !== undefined && value !== null && value !== ''));
  }

  function consensus(evidence, field, aliases = []) {
    const values = new Map();
    for (const item of evidence.filter((row) => row.ok)) {
      const raw = [field, ...aliases].map((key) => item.fields[key]).find((value) => value !== undefined && value !== '');
      if (raw === undefined) continue;
      const digits = field === 'asn' ? String(raw).replace(/\D/g, '') : '';
      const display = field === 'asn' && digits ? `AS${digits}` : String(raw).trim();
      const key = ['country_code', 'asn'].includes(field) ? display.toUpperCase() : display.toLocaleLowerCase();
      if (!values.has(key)) values.set(key, { display, sources: [] });
      values.get(key).sources.push(item.source);
    }
    const ordered = [...values.values()].sort((a, b) => b.sources.length - a.sources.length);
    if (!ordered.length) return null;
    return {
      value: ordered[0].display, agree: ordered[0].sources.length,
      observed: ordered.reduce((sum, item) => sum + item.sources.length, 0), sources: ordered[0].sources,
      conflict: ordered.length > 1 ? ordered.map((item) => ({ value: item.display, sources: item.sources })) : null
    };
  }

  function signalSummary(evidence, flag) {
    const positive = [], negative = [], unknown = [];
    for (const item of evidence.filter((row) => row.ok)) {
      if (!Object.prototype.hasOwnProperty.call(item.fields, flag)) unknown.push(item.source);
      else (item.fields[flag] ? positive : negative).push(item.source);
    }
    let state = 'unknown';
    if (positive.length && negative.length) state = 'disputed';
    else if (positive.length >= 2 || (flag === 'tor' && positive.length)) state = 'confirmed';
    else if (positive.length) state = 'reported';
    else if (negative.length) state = 'not_reported';
    return { state, positiveSources: positive, negativeSources: negative, unknownSources: unknown };
  }

  function finalizeIntel(ip, evidence) {
    const successful = evidence.filter((item) => item.ok);
    const trustedSuccessful = successful.filter((item) => item.source !== 'cngeo');
    const derived = {};
    const conflicts = [];
    for (const [field, aliases] of [['country', []], ['country_code', []], ['region', []], ['city', []], ['asn', ['origin_asn']], ['organization', []]]) {
      const value = consensus(evidence, field, aliases);
      if (value) derived[field] = value;
      if (value && value.conflict) conflicts.push({ field, values: value.conflict });
    }
    const signals = Object.fromEntries(['proxy', 'vpn', 'tor', 'datacenter', 'abuser'].map((flag) => [flag, signalSummary(evidence, flag)]));
    for (const [flag, value] of Object.entries(signals)) {
      if (value.state === 'disputed') conflicts.push({ field: flag, true: value.positiveSources, false: value.negativeSources });
    }
    const riskScores = Object.fromEntries(successful.filter((item) => Number.isFinite(Number(item.fields.risk)))
      .map((item) => [item.source, Math.max(0, Math.min(100, Number(item.fields.risk))) ]));
    const importantConflict = conflicts.some((item) => ['country_code', 'asn'].includes(item.field));
    const keyFieldsConfirmed = (derived.country_code?.agree || 0) >= 2 && (derived.asn?.agree || 0) >= 2;
    const confidence = trustedSuccessful.length >= 3 && !importantConflict && keyFieldsConfirmed
      ? { level: 'high', reason: '至少三源成功，国家代码和 ASN 均至少双源一致' }
      : trustedSuccessful.length >= 2 ? { level: 'medium', reason: '多源可用，请检查冲突列表' }
        : trustedSuccessful.length === 1 ? { level: 'low', reason: '仅一个可信来源成功；国内镜像不提高置信度' }
          : { level: 'none', reason: '没有来源返回可用证据' };
    return { ip, queriedAt: now(), status: trustedSuccessful.length >= 2 ? 'ok' : trustedSuccessful.length ? 'partial' : 'failed', confidence, consensus: derived, conflicts, signals, riskScores, evidence };
  }

  function cacheGet(ip, fresh) {
    if (fresh) return null;
    const cache = GM_getValue(EVIDENCE_CACHE_KEY, {});
    const item = cache && cache[ip];
    const age = item ? Date.now() - Number(item.storedAt || 0) : Infinity;
    if (!item || age < 0 || age > EVIDENCE_CACHE_TTL) return null;
    return { ...item.result, cache: { hit: true, ageSeconds: Math.floor(age / 1000), ttlSeconds: EVIDENCE_CACHE_TTL / 1000 } };
  }

  function cachePut(ip, result) {
    if (result.status === 'failed') return;
    const cache = GM_getValue(EVIDENCE_CACHE_KEY, {});
    cache[ip] = { storedAt: Date.now(), result };
    const newest = Object.entries(cache).sort((a, b) => Number(b[1].storedAt || 0) - Number(a[1].storedAt || 0)).slice(0, 1000);
    GM_setValue(EVIDENCE_CACHE_KEY, Object.fromEntries(newest));
  }

  async function inspectIp(ip, fresh = false) {
    const cached = cacheGet(ip, fresh);
    if (cached) return cached;
    const encoded = encodeURIComponent(ip);
    const definitions = [
      ['ipapi', `https://api.ipapi.is/?q=${encoded}`],
      ['proxycheck', `https://proxycheck.io/v2/${encoded}?vpn=1&asn=1&risk=1&seen=1`],
      ['geojs', `https://get.geojs.io/v1/ip/geo/${encoded}.json`],
      ['rdap', `https://rdap.org/ip/${encoded}`],
      ['ripestat', `https://stat.ripe.net/data/routing-status/data.json?resource=${encoded}`]
    ];
    const evidence = await Promise.all(definitions.map(async ([source, url]) => {
      const queriedAt = now();
      try {
        if (source === 'rdap') await throttleRdap();
        const response = await request({ url });
        let data = null;
        try { data = JSON.parse(response.text); } catch (_) { data = { excerpt: response.text.slice(0, 240) }; }
        if (response.status < 200 || response.status >= 300) throw new Error(`HTTP ${response.status}`);
        const fields = providerFields(source, ip, data);
        return { source, queriedAt, elapsedMs: response.elapsedMs, status: response.status, ok: true, fields, data };
      } catch (error) {
        return { source, queriedAt, ok: false, error: error.message };
      }
    }));
    const globalGeoSuccess = evidence.filter((item) => item.ok && ['ipapi', 'proxycheck', 'geojs'].includes(item.source)).length;
    if (globalGeoSuccess < 2) {
      const queriedAt = now();
      try {
        const response = await request({ url: `https://www.cip.cc/${encoded}`, headers: { Accept: 'text/html' } });
        if (response.status !== 200) throw new Error(`HTTP ${response.status}`);
        const doc = new DOMParser().parseFromString(response.text, 'text/html');
        const text = (doc.querySelector('pre')?.textContent || '').trim();
        const fields = {};
        for (const line of text.split(/\r?\n/)) {
          const match = line.match(/^\s*(IP|地址|运营商|数据二|数据三)\s*[:：]\s*(.*)$/);
          if (match) fields[{ IP: 'ip', 地址: 'location', 运营商: 'organization', 数据二: 'secondary', 数据三: 'english_location' }[match[1]]] = match[2].trim();
        }
        if (canonicalIp(fields.ip) !== canonicalIp(ip)) throw new Error('镜像未回显目标 IP');
        fields.trust_tier = 'fallback-unverified';
        evidence.push({ source: 'cngeo', queriedAt, elapsedMs: response.elapsedMs, status: response.status, ok: true, fields,
          warning: '国内备用镜像，非权威注册库，不参与高置信度判定' });
      } catch (error) { evidence.push({ source: 'cngeo', queriedAt, ok: false, error: error.message }); }
    }
    const result = finalizeIntel(ip, evidence);
    cachePut(ip, result);
    return result;
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
    const observations = await Promise.all(attempts.map(async (url) => {
      try {
        const response = await request({ url });
        const data = JSON.parse(response.text);
        const ip = data.ip;
        if (!ip || isPrivateHost(ip)) throw new Error('未返回公网 IP');
        return { url, ip, ok: true, elapsedMs: response.elapsedMs };
      } catch (error) {
        return { url, ok: false, error: error.message };
      }
    }));
    const successful = observations.filter((item) => item.ok);
    if (!successful.length) throw new Error(`出口 IP 检测失败：${observations.map((item) => `${item.url}: ${item.error}`).join('; ')}`);
    const votes = new Map();
    for (const item of successful) votes.set(item.ip, (votes.get(item.ip) || 0) + 1);
    const ip = [...votes].sort((a, b) => b[1] - a[1])[0][0];
    return {
      route: '当前浏览器/扩展所用系统路由', discoveredAt: now(), ip,
      agreement: { matchingSources: votes.get(ip), successfulSources: successful.length, observations },
      details: await inspectIp(ip, true)
    };
  }

  async function inspectSubscription(url, allowPrivate, enrich, fresh = false) {
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
    const providerUrls = [...new Set(main.providers)].slice(0, MAX_PROVIDERS);
    const providerReports = await Promise.all(providerUrls.map(async (providerUrl) => {
      try {
        const report = await downloadSubscription(providerUrl, allowPrivate, 'proxy-provider');
        return { host: new URL(providerUrl).hostname, ok: true, nodes: report.nodes.length, report };
      } catch (error) {
        return { host: (() => { try { return new URL(providerUrl).hostname; } catch (_) { return 'invalid'; } })(), ok: false, error: error.message };
      }
    }));
    for (const item of providerReports) {
      if (item.ok) main.nodes.push(...item.report.nodes);
      delete item.report;
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
    const uniqueHosts = [...new Set(deduped.map((item) => item.host))];
    setStatus(`正在解析节点域名 0/${uniqueHosts.length}`);
    const hostAnswers = await mapLimit(uniqueHosts, 8, async (host) => ({ host, addresses: await resolveHost(host) }),
      (done, total) => setStatus(`正在解析节点域名 ${done}/${total}（从未连接节点端口）`));
    const addressMap = new Map(hostAnswers.map((item) => [item.host, item.addresses]));
    const resolved = deduped.map((item) => {
      const addresses = addressMap.get(item.host) || [];
      return {
        ...item,
        addresses: addresses.filter((ip) => !isPrivateHost(ip)),
        rejectedAddresses: addresses.filter(isPrivateHost)
      };
    });
    const ips = [...new Set(resolved.flatMap((item) => item.addresses))];
    let intelligence = [];
    if (enrich && ips.length) {
      const targets = ips.slice(0, 30);
      intelligence = await mapLimit(targets, 4, (ip) => inspectIp(ip, fresh), (done, total) => setStatus(`正在查询 IP 情报 ${done}/${total}`));
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

  async function detailedInvestigation(value) {
    const ips = extractIps(value);
    if (ips.length !== 1 || String(value).match(/(?:\d{1,3}\.){3}\d{1,3}|(?:[0-9a-f]{0,4}:){2,}[0-9a-f:.]{0,39}/gi)?.length !== 1) {
      throw new Error('详细调查模式一次只接受一个公网 IP；私网/保留地址被拒绝');
    }
    const ip = ips[0];
    const encoded = encodeURIComponent(ip);
    const standard = await inspectIp(ip, true);
    const definitions = [
      ['rdap-current-holder', `https://rdap.org/ip/${encoded}`],
      ['ripestat-network', `https://stat.ripe.net/data/network-info/data.json?resource=${encoded}`],
      ['ripestat-whois', `https://stat.ripe.net/data/whois/data.json?resource=${encoded}`],
      ['ripestat-abuse', `https://stat.ripe.net/data/abuse-contact-finder/data.json?resource=${encoded}`],
      ['ripestat-visibility', `https://stat.ripe.net/data/visibility/data.json?resource=${encoded}`],
      ['shodan-internetdb', `https://internetdb.shodan.io/${encoded}`],
      ['greynoise-community', `https://api.greynoise.io/v3/community/${encoded}`]
    ];
    const evidence = await mapLimit(definitions, 6, async ([source, url]) => {
      const queriedAt = now();
      try {
        const response = await request({ url, headers: { Accept: 'application/json' } });
        if (![200, 404].includes(response.status)) throw new Error(`HTTP ${response.status}`);
        let data; try { data = JSON.parse(response.text); } catch (_) { data = { excerpt: response.text.slice(0, 2000) }; }
        return { source, ok: true, queriedAt, status: response.status, elapsedMs: response.elapsedMs, data };
      } catch (error) { return { source, ok: false, queriedAt, error: error.message }; }
    });
    const internetDb = evidence.find((item) => item.source === 'shodan-internetdb' && item.ok)?.data || {};
    const verifiedNames = [];
    for (const host of (internetDb.hostnames || []).slice(0, 12)) {
      const addresses = await resolveHost(host);
      if (addresses.some((address) => canonicalIp(address) === canonicalIp(ip))) verifiedNames.push(host);
      if (verifiedNames.length >= 5) break;
    }
    const certificateTransparency = await mapLimit(verifiedNames, 3, async (host) => {
      try {
        const response = await request({ url: `https://crt.sh/?q=${encodeURIComponent(host)}&output=json`, headers: { Accept: 'application/json' } });
        if (response.status !== 200) throw new Error(`HTTP ${response.status}`);
        return { host, currentlyResolvesToTarget: true, ok: true, records: JSON.parse(response.text).slice(0, 100), queriedAt: now() };
      } catch (error) { return { host, currentlyResolvesToTarget: true, ok: false, error: error.message, queriedAt: now() }; }
    });
    return {
      kind: 'single-ip-detailed-investigation', ip, checkedAt: now(), standard, passivePublicEvidence: evidence,
      certificateTransparency,
      tlsCertificateBoundary: '浏览器扩展 API 不暴露当前 TLS 对端证书。这里提供已正向验证到目标 IP 的主机名之公开 CT 历史；实时 443 证书、TLS 版本和指纹请使用 Android/iOS/桌面版。',
      activeTargetConnections: [], portScanPerformed: false,
      truthBoundary: [
        '没有有限工具能保证覆盖所有公网记录；报告只对列出的来源、查询时间、HTTP 状态和失败负责。',
        'Shodan 端口/CVE、GreyNoise 活动与 CT 历史是第三方被动观测，可能陈旧、不完整或错误。',
        'RDAP 登记国家不等于服务器物理位置，abuse 联系信息可能失效。',
        '国内镜像仅在全球地理源不足时作为低可信旁证，永不单独提高置信度。'
      ]
    };
  }

  function validateController(raw) {
    let url;
    try { url = new URL(String(raw || '').trim() || 'http://127.0.0.1:9090'); }
    catch (_) { throw new Error('控制器地址无效'); }
    const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, '');
    if (url.protocol !== 'http:' || !['127.0.0.1', 'localhost', '::1'].includes(host) || !url.port || url.username || url.password || (url.pathname !== '/' && url.pathname !== '') || url.search || url.hash) {
      throw new Error('控制器只允许 http://127.0.0.1:端口、localhost 或 [::1]');
    }
    return url.origin;
  }

  async function controllerJson(base, path, secret, method = 'GET', body = null) {
    const response = await request({
      url: `${base}${path}`, method, anonymous: true, redirect: 'manual',
      headers: { Accept: 'application/json', ...(secret ? { Authorization: `Bearer ${secret}` } : {}), ...(body ? { 'Content-Type': 'application/json' } : {}) },
      data: body ? JSON.stringify(body) : undefined
    });
    if (response.status < 200 || response.status >= 300) throw new Error(`本机控制器 HTTP ${response.status}: ${response.text.slice(0, 300)}`);
    return response.text.trim() ? JSON.parse(response.text) : {};
  }

  async function exitSnapshot() {
    const urls = ['https://api.ipify.org?format=json', 'https://api64.ipify.org?format=json', 'https://get.geojs.io/v1/ip.json'];
    const observations = await Promise.all(urls.map(async (url) => {
      try { const response = await request({ url, anonymous: true }); const ip = JSON.parse(response.text).ip; return { url, ok: !isPrivateHost(ip), ip, status: response.status, elapsedMs: response.elapsedMs }; }
      catch (error) { return { url, ok: false, error: error.message }; }
    }));
    return { ips: [...new Set(observations.filter((item) => item.ok).map((item) => item.ip))], observations };
  }

  async function realTargets(custom) {
    const raw = [
      ['ChatGPT', 'https://chatgpt.com/'], ['Claude', 'https://claude.ai/new'], ['Gemini', 'https://gemini.google.com/app'],
      ['AI Studio', 'https://aistudio.google.com/app/prompts/new_chat'], ['Grok', 'https://grok.com/'],
      ['Perplexity', 'https://www.perplexity.ai/'], ['Copilot', 'https://copilot.microsoft.com/'],
      ['DeepSeek', 'https://chat.deepseek.com/'], ['Qwen', 'https://chat.qwen.ai/']
    ];
    for (let value of String(custom || '').split(/[,\n]/).map((item) => item.trim()).filter(Boolean)) {
      if (!value.includes('://')) value = `https://${value}`;
      raw.push(['自定义', value]);
    }
    if (raw.length > 24) throw new Error('真实测试网址最多 24 个');
    const results = [];
    for (const [name, value] of raw) {
      const url = new URL(value);
      if (url.protocol !== 'https:' || url.username || url.password) throw new Error(`目标必须是无账号信息的 HTTPS 公网网址：${value}`);
      const addresses = await resolveHost(url.hostname);
      if (!addresses.length || addresses.some(isPrivateHost)) throw new Error(`拒绝解析到私网/保留地址的目标：${url.hostname}`);
      if (!results.some((item) => item.url === url.href)) results.push({ name, url: url.href, addressesBeforeSwitch: addresses });
    }
    return results;
  }

  function classifyReal(status, location, body) {
    const combined = `${location}\n${body}`.toLowerCase();
    if (['unsupported country', 'unsupported region', 'not available in your country', 'not available in your region', '地区不可用', '地区暂不支持'].some((value) => combined.includes(value))) return 'geo_blocked';
    if (status === 429) return 'rate_limited';
    if (status >= 500) return 'upstream_error';
    if ([401, 407].includes(status)) return 'authentication_required';
    if ([403, 503].includes(status) && /(cloudflare|captcha|challenge|cf-chl)/i.test(combined)) return 'challenge';
    if (status >= 300 && status < 400) return /(login|signin|auth|account)/i.test(location) ? 'authentication_required' : 'redirect';
    if (status >= 200 && status < 400) return /(sign in|log in|登录)/i.test(combined) ? 'reachable_auth_ui' : 'reachable';
    return 'blocked_or_rejected';
  }

  async function realProbe(target) {
    const queriedAt = now();
    try {
      const response = await request({ url: target.url, anonymous: true, redirect: 'manual', headers: { Accept: 'text/html,application/xhtml+xml,*/*;q=0.6' } });
      const location = response.headers.match(/^location:\s*(.+)$/im)?.[1]?.trim() || '';
      return { ...target, queriedAt, httpStatus: response.status, elapsedMs: response.elapsedMs,
        verdict: classifyReal(response.status, location, response.text.slice(0, 32768)), location, cookiesOrCredentialsSent: false };
    } catch (error) { return { ...target, queriedAt, verdict: /timeout/i.test(error.message) ? 'timeout' : 'network_error', error: error.message, cookiesOrCredentialsSent: false }; }
  }

  async function realSubscriptionTest(subscriptionUrl, controllerValue, secret, exactNode, customTargets, openBrowser) {
    const base = validateController(controllerValue);
    const version = await controllerJson(base, '/version', secret);
    const config = await controllerJson(base, '/configs', secret);
    const tunEnabled = typeof config.tun === 'object' ? Boolean(config.tun.enable) : Boolean(config.tun);
    if (!tunEnabled) throw new Error('本机控制器可访问，但 /configs 显示 TUN/系统 VPN 未启用');
    const subscription = await inspectSubscription(subscriptionUrl, false, false, true);
    const names = new Set(subscription.nodes.map((item) => item.name).filter(Boolean));
    if (!names.size) throw new Error('订阅没有可用于控制器匹配的节点名称');
    const root = await controllerJson(base, '/proxies', secret);
    const groups = Object.entries(root.proxies || {}).map(([name, item]) => ({ name, item,
      overlap: Array.isArray(item.all) ? item.all.filter((nodeName) => names.has(nodeName)) : [] }))
      .filter((item) => item.overlap.length).sort((a, b) => b.overlap.length - a.overlap.length);
    if (!groups.length) throw new Error('控制器策略组中找不到订阅的节点名称');
    const group = groups[0];
    const requested = String(exactNode || '').trim();
    if (requested && !group.overlap.includes(requested)) throw new Error('指定节点不同时存在于订阅和控制器策略组');
    const selected = requested ? [requested] : group.overlap.slice(0, 20);
    if (openBrowser && selected.length !== 1) throw new Error('打开对话页面必须填写一个精确节点名称');
    const targets = await realTargets(customTargets);
    const original = String(group.item.now || '');
    const baselineExit = await exitSnapshot();
    const results = [];
    let restored = false;
    let restoreError = null;
    try {
      for (const nodeName of selected) {
        await controllerJson(base, `/proxies/${encodeURIComponent(group.name)}`, secret, 'PUT', { name: nodeName });
        await new Promise((resolve) => setTimeout(resolve, 1400));
        const current = await controllerJson(base, '/proxies', secret);
        const actual = current.proxies?.[group.name]?.now || '';
        if (actual !== nodeName) { results.push({ node: nodeName, switchOk: false, actual }); continue; }
        const exit = await exitSnapshot();
        const checks = await mapLimit(targets, 6, realProbe, (done, total) => setStatus(`${nodeName} · 对话网址 ${done}/${total}`));
        results.push({ node: nodeName, switchOk: true, controllerConfirmed: actual, exit, targets: checks });
      }
    } finally {
      if (original && !openBrowser) {
        try { await controllerJson(base, `/proxies/${encodeURIComponent(group.name)}`, secret, 'PUT', { name: original }); restored = true; }
        catch (error) { restoreError = error.message; }
      }
    }
    if (openBrowser) targets.forEach((target) => window.open(target.url, '_blank', 'noopener'));
    return {
      kind: 'real-subscription-system-vpn-test', checkedAt: now(), controller: { base, version, tunEnabled, group: group.name,
        originalNode: original, originalRestored: restored, leftTestNodeForBrowser: openBrowser, restoreError, secretPersisted: false },
      subscription: { nodes: subscription.counts.nodes, matchedControllerNodes: group.overlap.length, testedNodes: selected.length, contentPersisted: false },
      baselineExit, results,
      semantics: { actualConversationUrls: true, browserPagesOpened: openBrowser, automatedCookiesOrCredentialsSent: false, messagesSent: false,
        meaning: '匿名 GM 请求经当前设备网络栈测试；登录跳转表示已到达，不等于地区封锁。打开页面模式使用浏览器自身登录状态。' },
      warnings: ['切换策略组会暂时影响该系统 VPN 的其他流量。', '分流规则可能让不同域名走不同线路，请结合逐节点出口。',
        '浏览器扩展受标签页生命周期限制，不等于 Android/iOS/桌面的后台服务。', '浏览器模式会按设计保留测试节点，完成后请在代理客户端恢复。']
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
    const results = await mapLimit(targets, 6, async ([name, url]) => {
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
      :host{all:initial} *{box-sizing:border-box} .panel{position:fixed;z-index:2147483647;right:18px;bottom:18px;width:min(720px,calc(100vw - 36px));max-height:calc(100vh - 36px);overflow:auto;background:#101722;color:#e8eef7;border:1px solid #39506d;border-radius:14px;box-shadow:0 18px 55px #0009;font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;padding:16px}.head{display:flex;gap:12px;align-items:center}.head h2{font-size:18px;margin:0;flex:1}.badge{font-size:11px;color:#91b7e6}.close{width:auto!important;background:#253449!important}.notice{background:#172538;border-left:3px solid #4ca6ff;padding:9px 11px;margin:12px 0;color:#d5e8ff}.grid{display:grid;grid-template-columns:1fr auto;gap:8px}.row{display:flex;gap:8px;flex-wrap:wrap;margin:9px 0}input[type=text],input[type=password],textarea{width:100%;background:#0b111a;color:#fff;border:1px solid #38516d;border-radius:8px;padding:9px}textarea{min-height:82px;resize:vertical}button{border:0;border-radius:8px;padding:9px 12px;background:#1976d2;color:white;font-weight:650;cursor:pointer}button.secondary{background:#334961}button:disabled{opacity:.5;cursor:wait}label{display:flex;gap:6px;align-items:center;color:#c9d8e8}.status{color:#91b7e6;margin:7px 0}.out{white-space:pre-wrap;word-break:break-word;background:#070b10;color:#cfe2f6;border:1px solid #26384d;border-radius:8px;padding:12px;min-height:180px;max-height:42vh;overflow:auto;font:12px/1.45 ui-monospace,SFMono-Regular,Consolas,monospace}@media(max-width:560px){.panel{right:8px;bottom:8px;width:calc(100vw - 16px);max-height:calc(100vh - 16px)}.grid{grid-template-columns:1fr}}
    `;
    panel = document.createElement('section');
    panel.className = 'panel';
    panel.innerHTML = `
      <div class="head"><h2>IPBatchInspector</h2><span class="badge">v${VERSION} · 油猴版</span><button class="close" data-action="close">关闭</button></div>
      <div class="notice">普通订阅体检只下载/解析、DoH 与公网 IP 情报，绝不连接节点端口。下方“真实测试”是独立的显式操作：只控制你已开启的本机 Mihomo/Clash 系统 VPN，并访问真实对话网址；油猴受标签页生命周期限制，不是系统后台服务。</div>
      <div class="row"><button data-action="exit">检测当前出口</button><button data-action="ai">AI 公开入口直测</button></div>
      <textarea data-field="ips" placeholder="粘贴公网 IPv4/IPv6；自动去重，最多 500 个"></textarea>
      <div class="row"><button data-action="scan">批量 IP 情报</button><button class="secondary" data-action="detail">单 IP 详细调查</button></div>
      <div class="grid"><input type="text" data-field="subscription" autocomplete="off" spellcheck="false" placeholder="HTTPS 订阅、sn://subscription…"><button data-action="subscription">只解析订阅</button></div>
      <div class="row"><label><input type="checkbox" data-field="allow-private">显式允许本机/私网订阅</label><label><input type="checkbox" data-field="enrich" checked>查询前 30 个节点 IP 的五源情报</label><label><input type="checkbox" data-field="fresh">强制刷新（忽略 15 分钟缓存）</label></div>
      <div class="notice">订阅真实测试（需先开启系统 VPN/TUN 与 External Controller；会临时切换策略组）</div>
      <input type="text" data-field="controller" value="http://127.0.0.1:9090" autocomplete="off" spellcheck="false" placeholder="本机控制器">
      <div class="grid"><input type="password" data-field="controller-secret" autocomplete="off" placeholder="控制器 Secret（不保存）"><input type="text" data-field="exact-node" autocomplete="off" placeholder="精确节点名；留空测前20个"></div>
      <textarea data-field="real-targets" placeholder="自定义 HTTPS 域名/网址，逗号或换行；内置 ChatGPT、Claude、Gemini、AI Studio、Grok、Perplexity、Copilot、DeepSeek、Qwen"></textarea>
      <div class="row"><label><input type="checkbox" data-field="open-browser">只测精确节点并打开真实对话页面；不恢复节点</label><button data-action="realtest">确认并真实测试</button></div>
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
        const fresh = panel.querySelector('[data-field="fresh"]').checked;
        const results = await mapLimit(ips, 4, (ip) => inspectIp(ip, fresh), (done, total) => setStatus(`批量 IP 情报 ${done}/${total}`));
        return { kind: 'batch-ip', checkedAt: now(), count: results.length, results };
      });
      if (action === 'detail') run('正在执行单 IP 详细调查…', () => detailedInvestigation(panel.querySelector('[data-field="ips"]').value));
      if (action === 'subscription') run('正在安全下载并解析订阅…', () => {
        const url = panel.querySelector('[data-field="subscription"]').value.trim();
        if (!url) throw new Error('请输入订阅地址');
        return inspectSubscription(url, panel.querySelector('[data-field="allow-private"]').checked, panel.querySelector('[data-field="enrich"]').checked, panel.querySelector('[data-field="fresh"]').checked);
      });
      if (action === 'realtest') run('正在核验系统 VPN 控制器并测试真实对话网址…', () => {
        const url = panel.querySelector('[data-field="subscription"]').value.trim();
        if (!url) throw new Error('请先填写或载入订阅链接');
        const browser = panel.querySelector('[data-field="open-browser"]').checked;
        const exact = panel.querySelector('[data-field="exact-node"]').value.trim();
        if (browser && !exact) throw new Error('打开对话页面时必须填写一个精确节点名');
        return realSubscriptionTest(url, panel.querySelector('[data-field="controller"]').value,
          panel.querySelector('[data-field="controller-secret"]').value, exact,
          panel.querySelector('[data-field="real-targets"]').value, browser);
      });
      if (action === 'save') run('正在加密保存…', async () => { await saveCurrentSubscription(); return { ok: true, savedAt: now(), plaintextStored: false }; });
      if (action === 'load') run('正在载入加密订阅…', async () => { await loadSavedSubscription(); return { ok: true, loadedAt: now() }; });
      if (action === 'export') downloadResult();
    });
  }

  GM_registerMenuCommand('打开 IPBatchInspector', buildPanel);
})();
