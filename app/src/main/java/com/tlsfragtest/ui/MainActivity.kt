package com.tlsfragtest.ui

import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.RadioGroup
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.tlsfragtest.R
import com.tlsfragtest.probe.Presets
import com.tlsfragtest.probe.ProbeMode
import com.tlsfragtest.probe.ProbeResult
import com.tlsfragtest.probe.TlsProbe
import kotlin.concurrent.thread

class MainActivity : AppCompatActivity() {

    private lateinit var etHost: EditText
    private lateinit var etPort: EditText
    private lateinit var etSni: EditText
    private lateinit var rgMode: RadioGroup
    private lateinit var rgTls: RadioGroup
    private lateinit var fragParams: LinearLayout
    private lateinit var etFrags: EditText
    private lateinit var etInterval: EditText
    private lateinit var etRecVer: EditText
    private lateinit var tvLog: TextView
    private lateinit var btnRun: Button
    private lateinit var btnRunAll: Button

    private fun log(s: String) {
        runOnUiThread {
            tvLog.append(s + "\n")
        }
    }

    private fun currentMode(): ProbeMode = when (rgMode.checkedRadioButtonId) {
        R.id.rbFrag -> ProbeMode.FRAG
        R.id.rbPlain -> ProbeMode.PLAIN
        else -> ProbeMode.REWRITE
    }

    private fun runOne(host: String, port: Int, sni: String) {
        val mode = currentMode()
        val tls13 = rgTls.checkedRadioButtonId == R.id.rbTls13
        val frags = etFrags.text.toString().toIntOrNull() ?: 4
        val interval = etInterval.text.toString().toLongOrNull() ?: 200L
        val recVer = etRecVer.text.toString().toIntOrNull(16) ?: 0x0301
        log("— ${mode.label} ${if (tls13) "TLS1.3" else "TLS1.2"} $host:$port SNI=$sni" +
            if (mode == ProbeMode.FRAG) " 片数=$frags 间隔=${interval}ms recVer=0x%04x".format(recVer) else "")
        val r: ProbeResult = try {
            TlsProbe.probe(host, port, sni, mode, tls13, frags, interval, recVer)
        } catch (e: Exception) {
            log("  异常: ${e.message}")
            return
        }
        val mark = if (r.verdict == "ServerHello") "✓" else "✗"
        log("  $mark ${r.verdict} ${r.serverVersion} TCP=${r.tcpMs}ms 总=${r.totalMs}ms 发=${r.sentBytes}B")
        log("    ${r.detail}")
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        etHost = findViewById(R.id.etHost)
        etPort = findViewById(R.id.etPort)
        etSni = findViewById(R.id.etSni)
        rgMode = findViewById(R.id.rgMode)
        rgTls = findViewById(R.id.rgTls)
        fragParams = findViewById(R.id.fragParams)
        etFrags = findViewById(R.id.etFrags)
        etInterval = findViewById(R.id.etInterval)
        etRecVer = findViewById(R.id.etRecVer)
        tvLog = findViewById(R.id.tvLog)
        btnRun = findViewById(R.id.btnRun)
        btnRunAll = findViewById(R.id.btnRunAll)

        rgMode.setOnCheckedChangeListener { _, _ ->
            fragParams.visibility = if (currentMode() == ProbeMode.FRAG) View.VISIBLE else View.GONE
        }

        // 预设按钮
        fun addPresetButtons(rowId: Int, presets: List<com.tlsfragtest.probe.Preset>) {
            val row = findViewById<LinearLayout>(rowId)
            for (p in presets) {
                val b = Button(this).apply {
                    text = p.name
                    textSize = 12f
                    setOnClickListener {
                        etHost.setText(p.connectHost)
                        etPort.setText(p.port.toString())
                        etSni.setText(p.sni)
                    }
                }
                row.addView(b)
            }
        }
        addPresetButtons(R.id.rowCf, Presets.cloudflare)
        addPresetButtons(R.id.rowTg, Presets.telegram)
        addPresetButtons(R.id.rowWeb, Presets.websites)

        btnRun.setOnClickListener {
            val host = etHost.text.toString().trim()
            val port = etPort.text.toString().toIntOrNull() ?: 443
            val sni = etSni.text.toString().trim().ifEmpty { host }
            if (host.isEmpty()) { log("先填连接地址"); return@setOnClickListener }
            btnRun.isEnabled = false
            btnRunAll.isEnabled = false
            thread {
                runOne(host, port, sni)
                runOnUiThread { btnRun.isEnabled = true; btnRunAll.isEnabled = true }
            }
        }

        btnRunAll.setOnClickListener {
            btnRun.isEnabled = false
            btnRunAll.isEnabled = false
            thread {
                log("== 全部预设（${currentMode().label}） ==")
                for (p in Presets.all) {
                    runOne(p.connectHost, p.port, p.sni)
                }
                log("== 跑完 ==")
                runOnUiThread { btnRun.isEnabled = true; btnRunAll.isEnabled = true }
            }
        }

        findViewById<Button>(R.id.btnClear).setOnClickListener { tvLog.text = "" }

        log("就绪。先选模式（默认 改写0304），点预设填目标，再点 测一次。")
        log("想对比：同一目标分别用 baseline / 改写0304 / 分片 各测一次。")
    }
}
