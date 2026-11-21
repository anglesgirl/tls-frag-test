package com.tlsfragtest.probe

/** 预设测试目标：连接地址 + SNI。 */
data class Preset(
    val name: String,
    val connectHost: String,
    val port: Int = 443,
    val sni: String = connectHost,
)

object Presets {
    /** Cloudflare IP：SNI 用 CF 托管的域名，看分片/改写对 CF IP 是否生效。 */
    val cloudflare = listOf(
        Preset("CF 104.16.132.229", "104.16.132.229", 443, "www.cloudflare.com"),
        Preset("CF 104.16.133.229", "104.16.133.229", 443, "www.cloudflare.com"),
        Preset("CF 172.67.0.1", "172.67.0.1", 443, "www.cloudflare.com"),
        Preset("CF 1.1.1.1", "1.1.1.1", 443, "one.one.one.one"),
        Preset("CF 104.20.43.242", "104.20.43.242", 443, "proxy.svc.litv.tv"),
    )

    /** Telegram DC（2026-11-21 实测修正）：活的是 149.154.161.145，149.154.170.200 已死。 */
    val telegram = listOf(
        Preset("TG zws1-1", "149.154.161.145", 443, "zws1-1.web.telegram.org"),
        Preset("TG zws1", "149.154.161.145", 443, "zws1.web.telegram.org"),
        Preset("TG t.me", "149.154.161.145", 443, "t.me"),
        Preset("TG web.telegram.org", "149.154.161.145", 443, "web.telegram.org"),
    )

    /** 网站：走系统 DNS 解析，看普通网站对分片/改写是否接受。 */
    val websites = listOf(
        Preset("维基百科中文", "zh.wikipedia.org"),
        Preset("维基百科", "www.wikipedia.org"),
        Preset("Google", "www.google.com"),
        Preset("Cloudflare 官网", "www.cloudflare.com"),
        Preset("GitHub", "github.com"),
    )

    val all: List<Preset> = cloudflare + telegram + websites
}
