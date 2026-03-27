const yaml = require('yaml');

function decodeBase64(str) {
  try {
    return Buffer.from(str, 'base64').toString('utf-8');
  } catch (e) {
    return str;
  }
}

function parseVless(uriStr) {
  const url = new URL(uriStr);
  const name = decodeURIComponent(url.hash.substring(1) || 'VLESS-Node');
  
  const proxy = {
    name: name,
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

  // Reality support
  if (url.searchParams.get('security') === 'reality') {
    proxy['reality-opts'] = {
      'public-key': url.searchParams.get('pbk') || '',
      'short-id': url.searchParams.get('sid') || ''
    };
  }

  // NetworkOpts
  if (proxy.network === 'ws') {
    proxy['ws-opts'] = {
      path: url.searchParams.get('path') || '/',
      headers: {
        Host: url.searchParams.get('host') || sni || url.hostname
      }
    };
  } else if (proxy.network === 'grpc') {
    proxy['grpc-opts'] = {
      'grpc-service-name': url.searchParams.get('serviceName') || ''
    };
  } else if (proxy.network === 'tcp') {
    const type = url.searchParams.get('headerType');
    if (type === 'http') {
      proxy['http-opts'] = {
        method: "GET",
        path: [(url.searchParams.get('path') || '/')],
        headers: {
          Host: [(url.searchParams.get('host') || sni || url.hostname)]
        }
      };
    }
  }

  return proxy;
}

function parseVmess(uriStr) {
  const base64Str = uriStr.replace('vmess://', '');
  const configStr = decodeBase64(base64Str);
  let config;
  try {
    config = JSON.parse(configStr);
  } catch (e) {
    return null;
  }

  const name = config.ps || 'VMess-Node';
  
  const proxy = {
    name: name,
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
      headers: {
        Host: config.host || config.sni || config.add
      }
    };
  } else if (proxy.network === 'grpc') {
    proxy['grpc-opts'] = {
      'grpc-service-name': config.path || ''
    };
  }

  return proxy;
}

function parseTrojan(uriStr) {
  const url = new URL(uriStr);
  const name = decodeURIComponent(url.hash.substring(1) || 'Trojan-Node');
  
  const proxy = {
    name: name,
    type: 'trojan',
    server: url.hostname,
    port: parseInt(url.port) || 443,
    password: url.username,
    network: url.searchParams.get('type') || 'tcp',
    tls: true, // Trojan implies TLS usually
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
      headers: {
        Host: url.searchParams.get('host') || sni || url.hostname
      }
    };
  } else if (proxy.network === 'grpc') {
    proxy['grpc-opts'] = {
      'grpc-service-name': url.searchParams.get('serviceName') || ''
    };
  }

  return proxy;
}

module.exports = async function handler(req, res) {
  const { url } = req.query;

  if (!url) {
    return res.status(400).json({ error: 'Missing "url" parameter' });
  }

  try {
    const response = await fetch(url, {
      headers: {
        'User-Agent': 'ClashforWindows/0.19.23' // Fake a Clash user agent so 3x-ui returns base64 instead of HTML
      }
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch subscription: ${response.statusText}`);
    }

    const text = await response.text();
    let decodedText = decodeBase64(text.trim());
    
    // Safety check: if it looks like HTML, fetching failed to sidestep the browser check
    if (decodedText.includes('<html') || text.includes('<html')) {
      throw new Error('Subscription URL returned an HTML page instead of node links.');
    }

    const lines = decodedText.split('\n').map(l => l.trim()).filter(l => l);
    
    const proxies = [];

    for (const line of lines) {
      try {
        if (line.startsWith('vless://')) {
          const proxy = parseVless(line);
          if (proxy) proxies.push(proxy);
        } else if (line.startsWith('vmess://')) {
          const proxy = parseVmess(line);
          if (proxy) proxies.push(proxy);
        } else if (line.startsWith('trojan://')) {
          const proxy = parseTrojan(line);
          if (proxy) proxies.push(proxy);
        }
      } catch (e) {
        console.error('Error parsing line:', line, e.message);
      }
    }

    if (proxies.length === 0) {
      return res.status(400).json({ error: 'No meaningful proxies found. Original response size: ' + text.length });
    }

    const config = { proxies };

    const yamlStr = yaml.stringify(config);

    res.setHeader('Content-Type', 'text/yaml; charset=utf-8');
    res.setHeader('Cache-Control', 's-maxage=600, stale-while-revalidate'); // cache on Vercel edge for 10 min
    res.status(200).send(yamlStr);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}
