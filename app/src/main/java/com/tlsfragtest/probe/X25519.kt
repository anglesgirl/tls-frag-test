package com.tlsfragtest.probe

import java.math.BigInteger
import java.security.SecureRandom

/**
 * X25519（RFC 7748）纯 Kotlin 实现，供 TLS 1.3 ClientHello 的 key_share 用。
 * 用 BigInteger 做模 p 运算，生成一次密钥够快；不依赖系统是否提供 X25519。
 */
object X25519 {
    // p = 2^255 - 19
    private val P = BigInteger("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16)
    private val A24 = BigInteger("121665")

    /** 生成一对 (私钥 32B, 公钥 32B)，私钥已按 RFC 7748 做 clamp。 */
    fun generateKeyPair(): Pair<ByteArray, ByteArray> {
        val priv = ByteArray(32).also { SecureRandom().nextBytes(it) }
        priv[0] = (priv[0].toInt() and 248).toByte()
        priv[31] = (priv[31].toInt() and 127).toByte()
        priv[31] = (priv[31].toInt() or 64).toByte()
        val base = ByteArray(32).also { it[0] = 9 }
        val pub = scalarMult(priv, base)
        return priv to pub
    }

    /** RFC 7748 Montgomery ladder：返回 scalar * u 的 X 坐标（小端 32 字节）。 */
    fun scalarMult(scalar: ByteArray, u: ByteArray): ByteArray {
        val x1 = fromLittleEndian(u)
        var x2 = BigInteger.ONE
        var z2 = BigInteger.ZERO
        var x3 = x1
        var z3 = BigInteger.ONE
        var swap = 0
        for (t in 254 downTo 0) {
            val kT = (scalar[t / 8].toInt() ushr (t % 8)) and 1
            swap = swap xor kT
            if (swap == 1) {
                val tx = x2; x2 = x3; x3 = tx
                val tz = z2; z2 = z3; z3 = tz
            }
            swap = kT
            val a = x2.add(z2).mod(P)
            val aa = a.multiply(a).mod(P)
            val b = x2.subtract(z2).mod(P)
            val bb = b.multiply(b).mod(P)
            val e = aa.subtract(bb).mod(P)
            val c = x3.add(z3).mod(P)
            val d = x3.subtract(z3).mod(P)
            val da = d.multiply(a).mod(P)
            val cb = c.multiply(b).mod(P)
            x3 = da.add(cb).mod(P).let { it.multiply(it).mod(P) }
            z3 = x1.multiply(da.subtract(cb).mod(P).let { it.multiply(it).mod(P) }).mod(P)
            x2 = aa.multiply(bb).mod(P)
            z2 = e.multiply(aa.add(A24.multiply(e)).mod(P)).mod(P)
        }
        if (swap == 1) {
            val tx = x2; x2 = x3; x3 = tx
            val tz = z2; z2 = z3; z3 = tz
        }
        // x2 * z2^(p-2) mod p
        val result = x2.multiply(z2.modPow(P.subtract(BigInteger.TWO), P)).mod(P)
        return toLittleEndian(result)
    }

    private fun fromLittleEndian(b: ByteArray): BigInteger {
        val be = b.reversedArray()
        return BigInteger(1, be)
    }

    private fun toLittleEndian(v: BigInteger): ByteArray {
        val be = v.toByteArray() // 大端，可能带前导 0
        val out = ByteArray(32)
        // 取低 32 字节，转小端
        val src = if (be.size > 32) be.copyOfRange(be.size - 32, be.size) else be
        for (i in src.indices) {
            out[i] = src[src.size - 1 - i]
        }
        return out
    }
}
