package com.tlsfragtest.probe

import java.io.ByteArrayOutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom

/** 探针模式 */
enum class ProbeMode(val label: String) {
    PLAIN("baseline 不改"),      // 单 record，版本 0301
    REWRITE("改写 0304"),       // 单 record，版本 0304
    FRAG("分片"),              // 多 record，可配片数/间隔
}

/** 握手结果 */
data class ProbeResult(
    val target: String,
    val mode: ProbeMode,
    val tlsLabel: String,
    val tcpMs: Long,
    val sentBytes: Int,
    val verdict: String,        // ServerHello / Alert / Timeout / RST / EOF / Other / TCP_FAIL
    val serverVersion: String,  // 如 0x0303
    val alertDesc: Int,         // Alert 描述码，-1 表示无
    val totalMs: Long,
    val detail: String,         // 补充说明（首字节 hex / 错误）
)

/**
 * TLS 握手探针：手工构造 ClientHello，按指定模式发送，
 * 只看服务器是否回 ServerHello（不完成握手，不做 VPN/代理）。
 *
 * 关键点（2026-11-21 参考对话实测）：
 * - 决定成败的不是分片，是首 record 版本：0301 -> 0304 单 record 就能过 DPI，
 *   分片（4 片 + 200ms）反而更容易 RESET。
 * - ClientHello 必须格式正确：SNI 长度字段、supported_versions 的向量长度字节
 *   （1 个版本 = 2 字节，不是 1）、TLS 1.3 必须带 key_share，否则服务器回
 *   BAD_EXTENSION / illegal_parameter / protocol_version。
 */
object TlsProbe {

    private fun u16(v: Int): ByteArray = byteArrayOf((v shr 8).toByte(), v.toByte())

    /** 构造 ClientHello 的 handshake 部分（不含 record 头）。 */
    fun buildClientHello(sni: String, tls13: Boolean): ByteArray {
        val out = ByteArrayOutputStream()
        val rnd = ByteArray(32).also { SecureRandom().nextBytes(it) }
        out.write(byteArrayOf(0x03, 0x03)) // client_version TLS 1.2
        out.write(rnd)
        out.write(0x00) // session_id len 0
        val suites = intArrayOf(
            0x1301, 0x1302, 0x1303, // TLS 1.3
            0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,
            0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
        )
        out.write(u16(suites.size * 2))
        for (s in suites) out.write(u16(s))
        out.write(byteArrayOf(0x01, 0x00)) // compression null

        val exts = ByteArrayOutputStream()
        // SNI
        val name = sni.toByteArray(Charsets.UTF_8)
        val entry = ByteArrayOutputStream().apply {
            write(0x00)
            write(u16(name.size))
            write(name)
        }.toByteArray()
        val sniData = ByteArrayOutputStream().apply {
            write(u16(entry.size))
            write(entry)
        }.toByteArray()
        exts.write(u16(0x0000)); exts.write(u16(sniData.size)); exts.write(sniData)
        // supported_versions：首字节是向量字节长度（每版本 2 字节）
        val sv = if (tls13) {
            byteArrayOf(0x04, 0x03, 0x04, 0x03, 0x03) // 2 个版本：1.3 + 1.2
        } else {
            byteArrayOf(0x02, 0x03, 0x03) // 1 个版本：1.2
        }
        exts.write(u16(0x002b)); exts.write(u16(sv.size)); exts.write(sv)
        // supported_groups
        val sg = ByteArrayOutputStream().apply {
            write(u16(6))
            write(u16(0x001d)); write(u16(0x0017)); write(u16(0x0018))
        }.toByteArray()
        exts.write(u16(0x000a)); exts.write(u16(sg.size)); exts.write(sg)
        // signature_algorithms
        val sa = ByteArrayOutputStream().apply {
            write(u16(8))
            write(u16(0x0403)); write(u16(0x0804)); write(u16(0x0401)); write(u16(0x0503))
        }.toByteArray()
        exts.write(u16(0x000d)); exts.write(u16(sa.size)); exts.write(sa)
        // ALPN h2, http/1.1
        val alpnList = ByteArrayOutputStream().apply {
            write(0x02); write("h2".toByteArray())
            write(0x08); write("http/1.1".toByteArray())
        }.toByteArray()
        val alpn = ByteArrayOutputStream().apply {
            write(u16(alpnList.size)); write(alpnList)
        }.toByteArray()
        exts.write(u16(0x0010)); exts.write(u16(alpn.size)); exts.write(alpn)
        // key_share（仅 TLS 1.3）：x25519
        if (tls13) {
            val (_, pub) = X25519.generateKeyPair()
            val share = ByteArrayOutputStream().apply {
                write(u16(0x001d))
                write(u16(pub.size))
                write(pub)
            }.toByteArray()
            val ks = ByteArrayOutputStream().apply {
                write(u16(share.size)); write(share)
            }.toByteArray()
            exts.write(u16(0x0033)); exts.write(u16(ks.size)); exts.write(ks)
        }

        val extBytes = exts.toByteArray()
        out.write(u16(extBytes.size))
        out.write(extBytes)

        val body = out.toByteArray()
        val hs = ByteArrayOutputStream().apply {
            write(0x01)
            write(byteArrayOf((body.size shr 16).toByte(), (body.size shr 8).toByte(), body.size.toByte()))
            write(body)
        }.toByteArray()
        return hs
    }

    /**
     * 对目标做一次握手探针。
     * @param connectHost 实际连接的 IP 或域名
     * @param port 端口（默认 443）
     * @param sni ClientHello 里带的 SNI（默认 = connectHost）
     * @param mode 探针模式
     * @param tls13 是否用 TLS 1.3（带 key_share），false 为 TLS 1.2
     * @param frags 分片模式的 record 数
     * @param intervalMs 分片间隔毫秒
     * @param recVer 分片/改写模式用的 record 版本（0x0301 或 0x0304）
     * @param timeoutMs 读取超时
     */
    fun probe(
        connectHost: String,
        port: Int = 443,
        sni: String = connectHost,
        mode: ProbeMode = ProbeMode.REWRITE,
        tls13: Boolean = true,
        frags: Int = 4,
        intervalMs: Long = 200,
        recVer: Int = 0x0301,
        timeoutMs: Int = 8000,
    ): ProbeResult {
        val target = "$connectHost:$port (SNI=$sni)"
        val tlsLabel = if (tls13) "TLS1.3" else "TLS1.2"
        val hs = buildClientHello(sni, tls13)
        val verBytes = byteArrayOf((recVer shr 8).toByte(), recVer.toByte())
        val t0 = System.currentTimeMillis()
        val sock = Socket()
        try {
            sock.connect(InetSocketAddress(connectHost, port), 5000)
        } catch (e: Exception) {
            return ProbeResult(target, mode, tlsLabel, -1, 0, "TCP_FAIL", "", -1,
                System.currentTimeMillis() - t0, "TCP 连接失败: ${e.message}")
        }
        val tcpMs = System.currentTimeMillis() - t0
        sock.soTimeout = timeoutMs
        var sent = 0
        try {
            val out = sock.getOutputStream()
            val recVerToUse = if (mode == ProbeMode.REWRITE) 0x0304 else recVer
            val vb = byteArrayOf((recVerToUse shr 8).toByte(), recVerToUse.toByte())
            when (mode) {
                ProbeMode.PLAIN, ProbeMode.REWRITE -> {
                    val rec = ByteArrayOutputStream().apply {
                        write(0x16); write(vb); write(u16(hs.size)); write(hs)
                    }.toByteArray()
                    out.write(rec); out.flush()
                    sent = rec.size
                }
                ProbeMode.FRAG -> {
                    val total = hs.size
                    val chunk = maxOf(1, total / frags)
                    var off = 0
                    while (off < total) {
                        val end = minOf(off + chunk, total)
                        val piece = hs.copyOfRange(off, end)
                        val rec = ByteArrayOutputStream().apply {
                            write(0x16); write(vb); write(u16(piece.size)); write(piece)
                        }.toByteArray()
                        out.write(rec); out.flush()
                        sent += rec.size
                        off = end
                        if (off < total && intervalMs > 0) Thread.sleep(intervalMs)
                    }
                }
            }
        } catch (e: Exception) {
            sock.close()
            return ProbeResult(target, mode, tlsLabel, tcpMs, sent, "RST",
                "", -1, System.currentTimeMillis() - t0, "发送时被 RST/断开: ${e.message}")
        }
        // 读回包：先攒够 6 字节（record 头 5 + handshake 类型 1）再判定，避免 TCP 分段误判
        val t1 = System.currentTimeMillis()
        val acc = ByteArrayOutputStream()
        val chunk = ByteArray(4096)
        return try {
            val inp = sock.getInputStream()
            while (acc.size() < 6) {
                val n = inp.read(chunk)
                if (n <= 0) break
                acc.write(chunk, 0, n)
                // 攒够 6 字节就够判定；ServerHello 通常一次就到齐
                if (acc.size() >= 6) break
            }
            // 再尽量多读一点（证书链等），但不阻塞太久
            sock.soTimeout = 1500
            try {
                while (true) {
                    val n = inp.read(chunk)
                    if (n <= 0) break
                    acc.write(chunk, 0, n)
                    if (acc.size() > 8192) break
                }
            } catch (_: java.net.SocketTimeoutException) {
                // 读够了，后续数据不等了
            }
            val buf = acc.toByteArray()
            val n = buf.size
            val totalMs = System.currentTimeMillis() - t0
            sock.close()
            if (n <= 0) {
                ProbeResult(target, mode, tlsLabel, tcpMs, sent, "EOF", "", -1,
                    totalMs, "服务器直接关连接（0 字节）")
            } else if (buf[0] == 0x16.toByte() && n >= 6 && buf[5] == 0x02.toByte()) {
                val sv = "0x%02x%02x".format(buf[9], buf[10])
                ProbeResult(target, mode, tlsLabel, tcpMs, sent, "ServerHello", sv, -1,
                    totalMs, "收到 ServerHello，${n}B")
            } else if (buf[0] == 0x15.toByte()) {
                val desc = if (n > 6) buf[6].toInt() and 0xFF else -1
                ProbeResult(target, mode, tlsLabel, tcpMs, sent, "Alert", "", desc,
                    totalMs, "服务器回 Alert，描述码=$desc（40=握手失败，70=协议版本，47=非法参数）")
            } else {
                val first = buf.copyOf(minOf(n, 16)).joinToString("") { "%02x".format(it) }
                ProbeResult(target, mode, tlsLabel, tcpMs, sent, "Other", "", -1,
                    totalMs, "非 TLS 回包，首字节=$first")
            }
        } catch (e: java.net.SocketTimeoutException) {
            sock.close()
            ProbeResult(target, mode, tlsLabel, tcpMs, sent, "Timeout", "", -1,
                System.currentTimeMillis() - t0, "8s 内无回包（可能被 DPI 丢包/黑洞）")
        } catch (e: Exception) {
            sock.close()
            ProbeResult(target, mode, tlsLabel, tcpMs, sent, "RST", "", -1,
                System.currentTimeMillis() - t0, "读取时断开: ${e.message}")
        }
    }
}
