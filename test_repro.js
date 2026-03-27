const yaml = require('yaml');

const proxies = [
  { name: 'Normal Node', type: 'vless', server: '1.2.3.4', port: 443 },
  { name: 'Node with : colon', type: 'vless', server: '1.2.3.4', port: 443 },
  { name: '[Tokyo] Node', type: 'vless', server: '1.2.3.4', port: 443 },
  { name: '{NY} Node', type: 'vless', server: '1.2.3.4', port: 443 },
  { name: 'Node | Vertical', type: 'vless', server: '1.2.3.4', port: 443 }
];

const config = { proxies };
const yamlStr = yaml.stringify(config);

console.log("--- YAML Output ---");
console.log(yamlStr);
console.log("--- End YAML ---");

try {
  const parsed = yaml.parse(yamlStr);
  console.log("Parsed successfully!");
  console.log("Node names:", parsed.proxies.map(p => p.name));
} catch (e) {
  console.error("Parse error:", e.message);
}
