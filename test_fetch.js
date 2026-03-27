const https = require('http');

https.get('http://156.246.95.108:2096/sub/1os0xrpn1e7hxqii', {
  headers: {
    'User-Agent': 'ClashforWindows/0.19.23'
  }
}, (res) => {
  let data = '';
  res.on('data', chunk => data += chunk);
  res.on('end', () => {
    console.log("Clash UA:", data);
  });
});

https.get('http://156.246.95.108:2096/sub/1os0xrpn1e7hxqii', {
  headers: {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36'
  }
}, (res) => {
  let data = '';
  res.on('data', chunk => data += chunk);
  res.on('end', () => {
    console.log("Browser UA:", data.substring(0, 100) + '...');
  });
});
