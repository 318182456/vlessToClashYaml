# 3x-ui to Mihomo Sub Converter

这个项目是一个轻量级的 Node.js Serverless Function，专为 Vercel 部署设计。
它能将 3x-ui 面板生成的订阅链接（包含 VLESS、VMess、Trojan 等节点）转换为 Mihomo (Clash Meta) 可用的 YAML 配置文件。

## 解决的问题
当您在浏览器直接访问 3x-ui 订阅链接时，由于 3x-ui 面板通常会根据 `User-Agent` 决定返回内容，如果是普通浏览器访问，它可能会返回一个包含二维码和节点列表的网页（HTML），而不是原始 Base64 订阅。
本工具在后台请求 3x-ui 数据时，会自动携带类似于 Clash 的 `User-Agent`，确保 3x-ui 总是返回正确的 Base64 订阅文本。接着，将解析各类节点 URI 为适合 Mihomo 规范的配置。

## 部署到 Vercel (一键部署)
[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/318182456/vlessToClashYaml&project-name=vlessToClashYaml&repository-name=vlessToClashYaml)

## 使用方法
项目部署成功后，假设 Vercel 为您分配的域名为 `https://your-vercel-domain.vercel.app`。

您可以在 Mihomo/Clash 的订阅提供程序（Providers）或配置 URL 处填入：
```
https://your-vercel-domain.vercel.app/sub?url=http://你的3x-ui域名或IP:端口/sub/1os0xrpn1e7hxqii
```

**参数说明**：
- `?url=` 后方紧跟您真实的 3x-ui 订阅链接。

## 本地测试
```bash
npm install
node test.js
```
