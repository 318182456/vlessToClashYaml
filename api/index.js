const yaml = require('yaml');

function decodeBase64(str) {
  try {
    // If it's already a link list or YAML, don't decode
    if (str.includes('://') || str.includes('proxies:')) {
      return str;
    }
    return Buffer.from(str, 'base64').toString('utf-8');
  } catch (e) {
    return str;
  }
}

function sanitizeName(name) {
  // Remove newlines and trim
  let n = name.replace(/[\r\n]+/g, ' ').trim();
  // Remove or replace characters that often break YAML if not quoted properly
  // Though we will force quoting, let's also remove colons just in case to be super safe
  n = n.replace(/:/g, '-');
  n = n.replace(/[\[\]\{\}]/g, '');
  return n;
}

function parseVless(uriStr) {
  const url = new URL(uriStr);
  const name = sanitizeName(decodeURIComponent(url.hash.substring(1) || 'VLESS-Node'));
  
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

  const name = sanitizeName(config.ps || 'VMess-Node');
  
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
  const name = sanitizeName(decodeURIComponent(url.hash.substring(1) || 'Trojan-Node'));
  
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
    res.setHeader('Content-Type', 'text/yaml; charset=utf-8');
    return res.status(200).send('# Missing "url" parameter\nproxies: []');
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
      // Return a valid but empty YAML instead of a JSON error to prevent Mihomo parsing issues
      res.setHeader('Content-Type', 'text/yaml; charset=utf-8');
      return res.status(200).send('proxies: []');
    }

    // Switch to JSON for maximum robustness. JSON is valid YAML.
    // This removes any ambiguity regarding indentation or special char quoting.
    const output = JSON.stringify({ proxies }, null, 2);

    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Cache-Control', 's-maxage=600, stale-while-revalidate'); 
    res.status(200).send(output);
  } catch (err) {
    // Return error as a JSON object that is still technically valid YAML
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.status(200).send(JSON.stringify({ 
      error: err.message,
      proxies: []
    }, null, 2));
  }
}
