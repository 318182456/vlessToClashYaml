const http = require('http');

function decodeBase64(str) {
  try {
    if (str.includes('://') || str.includes('proxies:')) {
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

module.exports = async function handler(req, res) {
  const { url } = req.query;

  res.setHeader('Content-Type', 'text/yaml; charset=utf-8');
  res.setHeader('Cache-Control', 's-maxage=60, stale-while-revalidate');

  if (!url) {
    return res.status(200).send('proxies: []\n');
  }

  try {
    const response = await fetch(url, {
      headers: { 'User-Agent': 'ClashforWindows/0.19.23' }
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

    // 手动拼接 YAML，完全掌控格式，避免 yaml 库输出 Mihomo 不兼容的格式
    const yamlStr = 'proxies:\n' + proxies.map(proxyToYaml).join('\n') + '\n';

    res.status(200).send(yamlStr);
  } catch (err) {
    res.status(200).send('proxies: []\n');
  }
}
