const handler = require('./api/index.js');

const req = {
  query: {
    url: 'http://156.246.95.108:2096/sub/1os0xrpn1e7hxqii'
  }
};

const res = {
  status(code) {
    this.code = code;
    return this;
  },
  json(data) {
    console.log(`[${this.code}] JSON:`, data);
    return this;
  },
  setHeader(k, v) {
    console.log(`Header: ${k} = ${v}`);
  },
  send(data) {
    console.log(`[${this.code}] Data:\n${data}`);
    return this;
  }
};

handler(req, res).then(() => {
  console.log('Test complete');
});
