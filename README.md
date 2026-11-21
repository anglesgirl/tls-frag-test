# TLS 握手探针（tls-frag-test）

测试用的 App：手工发 ClientHello，只看服务器是否回 ServerHello，**不做 VPN、不代理、不中转**。

## 测什么

三种模式，对比同一目标：

| 模式 | 做法 |
|---|---|
| baseline 不改 | 单 record，版本 0301 |
| 改写 0304 | 单 record，首 record 版本改成 0304 |
| 分片 | ClientHello 拆成 N 个 record，间隔发 |

## 背景（2026-11-21 实测）

- 关键不是分片，是 record 版本：把 ClientHello 首 record 版本从 0301 改成 0304，单 record 整发就能绕过 DPI；分片（4 片 + 200ms）实测反而更容易 RESET。
- ClientHello 必须格式正确：SNI 长度字段、supported_versions 的向量长度字节（1 个版本 = 2 字节）、TLS 1.3 必须带 key_share，否则服务器回 BAD_EXTENSION / illegal_parameter / protocol_version。
- TG 实测：zws1-1 / zws1 / t.me → 149.154.161.145 握手成功；zws5 / 149.154.170.200 回 Alert，已死。

## 预设

- Cloudflare IP：104.16.132.229、104.16.133.229、172.67.0.1、1.1.1.1、104.20.43.242
- Telegram DC（已修正）：zws1-1、zws1、t.me、web.telegram.org → 149.154.161.145
- 网站：zh.wikipedia.org、www.wikipedia.org、www.google.com、www.cloudflare.com、github.com

## 判定

- `✓ ServerHello`：能握手，该模式对该目标有效
- `✗ Alert`：服务器拒绝（描述码 40=握手失败，70=协议版本，47=非法参数）
- `✗ Timeout`：8s 无回包（可能被 DPI 丢包/黑洞）
- `✗ RST / EOF / TCP_FAIL`：连接被重置/关闭/连不上
