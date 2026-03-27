const http = require('http');
const dns = require('dns').promises;

// 判断是否为 IPv4 地址
function isIPv4(str) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(str);
}

// 域名解析为 IP，失败则返回原值
async function resolveServer(server) {
  if (isIPv4(server)) return server;
  try {
    const { address } = await dns.lookup(server, { family: 4 });
    return address;
  } catch {
    return server;
  }
}

function decodeBase64(str) {
  try {
    // 仅当字符串明确是 vless/vmess/trojan 链接或已是 YAML proxies 列表时跳过解码
    if (str.startsWith('vless://') || str.startsWith('vmess://') || str.startsWith('trojan://') || str.startsWith('proxies:')) {
      return str;
    }
    return Buffer.from(str, 'base64').toString('utf-8');
  } catch (e) {
    return str;
  }
}

function sanitizeName(name) {
  return name.replace(/[\r\n]+/g, ' ').trim();
}

// 将单个 proxy 对象序列化为 YAML 列表项（手动拼接，避免库的兼容性问题）
function proxyToYaml(p) {
  let lines = [];
  lines.push(`  - name: "${p.name.replace(/"/g, "'")}"`);
  lines.push(`    type: ${p.type}`);
  lines.push(`    server: ${p.server}`);
  lines.push(`    port: ${p.port}`);
  if (p.type === 'vless') {
    lines.push(`    uuid: ${p.uuid}`);
  } else if (p.type === 'vmess') {
    lines.push(`    uuid: ${p.uuid}`);
    lines.push(`    alterId: ${p.alterId || 0}`);
    lines.push(`    cipher: ${p.cipher || 'auto'}`);
  } else if (p.type === 'trojan') {
    lines.push(`    password: ${p.password}`);
  }
  lines.push(`    network: ${p.network}`);
  lines.push(`    tls: ${p.tls}`);
  if (p.flow) lines.push(`    flow: ${p.flow}`);
  lines.push(`    udp: ${p.udp}`);
  if (p.sni) lines.push(`    servername: ${p.sni}`);
  if (p['client-fingerprint']) lines.push(`    client-fingerprint: ${p['client-fingerprint']}`);
  if (p.alpn && p.alpn.length > 0) {
    lines.push(`    alpn:`);
    p.alpn.forEach(a => lines.push(`      - ${a}`));
  }
  if (p['ws-opts']) {
    lines.push(`    ws-opts:`);
    lines.push(`      path: "${p['ws-opts'].path || '/'}"`);
    if (p['ws-opts'].headers && p['ws-opts'].headers.Host) {
      lines.push(`      headers:`);
      lines.push(`        Host: ${p['ws-opts'].headers.Host}`);
    }
  }
  if (p['grpc-opts']) {
    lines.push(`    grpc-opts:`);
    lines.push(`      grpc-service-name: "${p['grpc-opts']['grpc-service-name'] || ''}"`);
  }
  if (p['reality-opts']) {
    lines.push(`    reality-opts:`);
    lines.push(`      public-key: ${p['reality-opts']['public-key']}`);
    lines.push(`      short-id: "${p['reality-opts']['short-id']}"`);
  }
  if (p['http-opts']) {
    lines.push(`    http-opts:`);
    lines.push(`      method: GET`);
    lines.push(`      path:`);
    (p['http-opts'].path || ['/']).forEach(pt => lines.push(`        - "${pt}"`));
    if (p['http-opts'].headers && p['http-opts'].headers.Host) {
      lines.push(`      headers:`);
      lines.push(`        Host:`);
      (p['http-opts'].headers.Host || []).forEach(h => lines.push(`          - ${h}`));
    }
  }
  return lines.join('\n');
}

function parseVless(uriStr) {
  const url = new URL(uriStr);
  const name = sanitizeName(decodeURIComponent(url.hash.substring(1) || 'VLESS-Node'));

  const proxy = {
    name,
    type: 'vless',
    server: url.hostname,
    port: parseInt(url.port) || 443,
    uuid: url.username,
    network: url.searchParams.get('type') || 'tcp',
    tls: url.searchParams.get('security') === 'tls' || url.searchParams.get('security') === 'reality',
    udp: true
  };

  const fp = url.searchParams.get('fp');
  if (fp) proxy['client-fingerprint'] = fp;

  const sni = url.searchParams.get('sni');
  if (sni) proxy.sni = sni;

  const alpn = url.searchParams.get('alpn');
  if (alpn) proxy.alpn = alpn.split(',');

  const flow = url.searchParams.get('flow');
  if (flow) proxy.flow = flow;

  if (url.searchParams.get('security') === 'reality') {
    proxy['reality-opts'] = {
      'public-key': url.searchParams.get('pbk') || '',
      'short-id': url.searchParams.get('sid') || ''
    };
  }

  if (proxy.network === 'ws') {
    proxy['ws-opts'] = {
      path: url.searchParams.get('path') || '/',
      headers: { Host: url.searchParams.get('host') || sni || url.hostname }
    };
  } else if (proxy.network === 'grpc') {
    proxy['grpc-opts'] = { 'grpc-service-name': url.searchParams.get('serviceName') || '' };
  } else if (proxy.network === 'tcp') {
    const headerType = url.searchParams.get('headerType');
    if (headerType === 'http') {
      proxy['http-opts'] = {
        method: 'GET',
        path: [url.searchParams.get('path') || '/'],
        headers: { Host: [url.searchParams.get('host') || sni || url.hostname] }
      };
    }
  }

  return proxy;
}

function parseVmess(uriStr) {
  const base64Str = uriStr.replace('vmess://', '');
  let config;
  try {
    config = JSON.parse(Buffer.from(base64Str, 'base64').toString('utf-8'));
  } catch (e) {
    return null;
  }

  const proxy = {
    name: sanitizeName(config.ps || 'VMess-Node'),
    type: 'vmess',
    server: config.add || config.host,
    port: parseInt(config.port) || 443,
    uuid: config.id,
    alterId: parseInt(config.aid) || 0,
    cipher: (config.scy === 'none' || config.scy === 'auto') ? 'auto' : (config.scy || 'auto'),
    network: config.net || 'tcp',
    tls: config.tls === 'tls',
    udp: true
  };

  if (config.sni) proxy.sni = config.sni;
  if (config.fp) proxy['client-fingerprint'] = config.fp;
  if (config.alpn) proxy.alpn = config.alpn.split(',');

  if (proxy.network === 'ws') {
    proxy['ws-opts'] = {
      path: config.path || '/',
      headers: { Host: config.host || config.sni || config.add }
    };
  } else if (proxy.network === 'grpc') {
    proxy['grpc-opts'] = { 'grpc-service-name': config.path || '' };
  }

  return proxy;
}

function parseTrojan(uriStr) {
  const url = new URL(uriStr);
  const name = sanitizeName(decodeURIComponent(url.hash.substring(1) || 'Trojan-Node'));

  const proxy = {
    name,
    type: 'trojan',
    server: url.hostname,
    port: parseInt(url.port) || 443,
    password: url.username,
    network: url.searchParams.get('type') || 'tcp',
    tls: true,
    udp: true
  };

  const sni = url.searchParams.get('sni');
  if (sni) proxy.sni = sni;
  const fp = url.searchParams.get('fp');
  if (fp) proxy['client-fingerprint'] = fp;
  const alpn = url.searchParams.get('alpn');
  if (alpn) proxy.alpn = alpn.split(',');

  if (proxy.network === 'ws') {
    proxy['ws-opts'] = {
      path: url.searchParams.get('path') || '/',
      headers: { Host: url.searchParams.get('host') || sni || url.hostname }
    };
  } else if (proxy.network === 'grpc') {
    proxy['grpc-opts'] = { 'grpc-service-name': url.searchParams.get('serviceName') || '' };
  }

  return proxy;
}

// 动态获取并解析 INI 文件内容
async function fetchAndParseIni(nodeNames, iniUrl) {
  try {
    const response = await fetch(iniUrl);
    if (!response.ok) throw new Error('Failed to fetch INI');
    const text = await response.text();
    const lines = text.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith(';'));

    const proxyGroups = [];
    const ruleProviders = {};
    const rules = [];

    for (const line of lines) {
      if (line.startsWith('custom_proxy_group=')) {
        const parts = line.substring('custom_proxy_group='.length).split('\`');
        const name = parts[0];
        const type = parts[1] || 'select';
        const proxies = [];

        for (let i = 2; i < parts.length; i++) {
          let member = parts[i];
          if (!member) continue;
          if (member.startsWith('[]')) {
            proxies.push(member.substring(2));
          } else if (member.startsWith('!!')) {
            // 简单处理排除项（暂不支持复杂正则排除）
          } else {
            try {
              const regex = new RegExp(member);
              const matched = nodeNames.filter(n => regex.test(n));
              if (matched.length > 0) proxies.push(...matched);
            } catch(e) { /* fallback */ }
          }
        }
        proxyGroups.push({ name, type, proxies: [...new Set(proxies)] });
      } else if (line.startsWith('ruleset=')) {
        const val = line.substring('ruleset='.length);
        const firstComma = val.indexOf(',');
        if (firstComma === -1) continue;
        const groupName = val.substring(0, firstComma);
        const ruleData = val.substring(firstComma + 1);

        if (ruleData.startsWith('[]')) {
          const content = ruleData.substring(2);
          if (content === 'FINAL') {
            rules.push(`  - MATCH,${groupName}`);
          } else {
            const ruleTypeParts = content.split(',');
            rules.push(`  - ${ruleTypeParts[0]},${ruleTypeParts[1]},${groupName}`);
          }
        } else {
          const url = ruleData;
          let providerNameOriginal = url.split('/').pop().replace('.list', '').replace(/[^a-zA-Z0-9_\-]/g, '');
          let providerName = providerNameOriginal;
          let counter = 1;
          while (ruleProviders[providerName] && ruleProviders[providerName].url !== url) {
            providerName = providerNameOriginal + counter;
            counter++;
          }
          ruleProviders[providerName] = {
            type: 'http',
            behavior: 'classical',
            url: url,
            path: `./ruleset/${providerName}.yaml`,
            interval: 86400
          };
          rules.push(`  - RULE-SET,${providerName},${groupName}`);
        }
      }
    }

    let pgYaml = 'proxy-groups:\n';
    for (const g of proxyGroups) {
      pgYaml += `  - name: ${g.name}\n`;
      pgYaml += `    type: ${g.type}\n`;
      pgYaml += `    proxies:\n`;
      for (const p of g.proxies) {
        pgYaml += `      - "${p.replace(/"/g, "'")}"\n`;
      }
    }

    let rpYaml = 'rule-providers:\n';
    for (const [name, p] of Object.entries(ruleProviders)) {
      rpYaml += `  ${name}:\n`;
      rpYaml += `    type: ${p.type}\n`;
      rpYaml += `    behavior: ${p.behavior}\n`;
      rpYaml += `    url: "${p.url}"\n`;
      rpYaml += `    path: ${p.path}\n`;
      rpYaml += `    interval: ${p.interval}\n`;
    }

    let rYaml = 'rules:\n';
    for (const r of rules) {
      rYaml += `${r}\n`;
    }

    return { proxyGroups: pgYaml, ruleProviders: rpYaml, rules: rYaml };
  } catch(e) {
    return null;
  }
}

module.exports = async function handler(req, res) {
  const { url, ini } = req.query;

  res.setHeader('Content-Type', 'text/yaml; charset=utf-8');
  res.setHeader('Cache-Control', 's-maxage=60, stale-while-revalidate');

  if (!url) {
    return res.status(200).send('proxies: []\n');
  }

  try {
    const response = await fetch(url, {
      // 使用 v2rayN UA，让 3x-ui 返回 base64 VLESS 格式，而非 Clash YAML
      // Clash UA 会导致 3x-ui 返回其自生成的 YAML（short-id 可能不同且格式有误）
      headers: { 'User-Agent': 'v2rayN/6.23' }
    });

    if (!response.ok) {
      return res.status(200).send('proxies: []\n');
    }

    const text = await response.text();
    let decodedText = decodeBase64(text.trim());

    if (decodedText.includes('<html') || text.includes('<html')) {
      return res.status(200).send('proxies: []\n');
    }

    const lines = decodedText.split('\n').map(l => l.trim()).filter(l => l);
    const proxies = [];

    for (const line of lines) {
      try {
        if (line.startsWith('vless://')) {
          const p = parseVless(line);
          if (p) proxies.push(p);
        } else if (line.startsWith('vmess://')) {
          const p = parseVmess(line);
          if (p) proxies.push(p);
        } else if (line.startsWith('trojan://')) {
          const p = parseTrojan(line);
          if (p) proxies.push(p);
        }
      } catch (e) {
        // 跳过无法解析的行
      }
    }

    if (proxies.length === 0) {
      return res.status(200).send('proxies: []\n');
    }

    // 并行将所有域名 server 解析为 IP
    await Promise.all(proxies.map(async p => {
      p.server = await resolveServer(p.server);
    }));

    // ====== 动态解析 INI 获取规则/策略组 ======
    const nodeNames = proxies.map(p => p.name);
    const iniUrl = ini || 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_NoAuto.ini';
    const parsedConfig = await fetchAndParseIni(nodeNames, iniUrl);
    const proxiesYaml = 'proxies:\n' + proxies.map(proxyToYaml).join('\n') + '\n';

    if (!parsedConfig) {
      // 若获取或者解析失败，回退到只生成 proxies
      return res.status(200).send(proxiesYaml);
    }

    // 基础配置
    const baseConfig = `
mode: rule
log-level: info
allow-lan: true
external-controller: :9090
dns:
  enable: true
  ipv6: false
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  nameserver:
    - 114.114.114.114
    - 223.5.5.5
    - 8.8.8.8
    - 1.1.1.1
`;

    // 拼接并返回完整 YAML
    const finalYaml = [
      baseConfig.trim(),
      proxiesYaml.trim(),
      parsedConfig.proxyGroups.trim(),
      parsedConfig.ruleProviders.trim(),
      parsedConfig.rules.trim()
    ].join('\n\n') + '\n';

    res.status(200).send(finalYaml);
  } catch (err) {
    res.status(200).send('proxies: []\n');
  }
}
