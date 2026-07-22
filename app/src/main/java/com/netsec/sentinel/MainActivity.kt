package com.netsec.sentinel

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.animation.*
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.blur
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import java.security.MessageDigest
import java.util.Base64

// --------------------------------------------------------------------
// [CYBERPUNK NEON COLOR PALETTE & STYLES]
// --------------------------------------------------------------------
val NeonGreen = Color(0xFF00FF66)
val NeonCyan = Color(0xFF00E5FF)
val NeonPink = Color(0xFFFF007F)
val DarkBackground = Color(0xFF0A0E17)
val GlassCardBackground = Color(0x1A1E293B)
val BorderColor = Color(0xFF1E293B)

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            NetSecSentinelApp()
        }
    }
}

// --------------------------------------------------------------------
// [VIEWMODEL: NON-ROOT DIAGNOSTIC ENGINE]
// --------------------------------------------------------------------
class SecurityEngineViewModel : ViewModel() {

    private val _outputState = MutableStateFlow<List<String>>(emptyList())
    val outputState: StateFlow<List<String>> = _outputState

    private val _isLoading = MutableStateFlow(false)
    val isLoading: StateFlow<Boolean> = _isLoading

    private fun log(message: String) {
        _outputState.value = _outputState.value + message
    }

    private fun clearLog() {
        _outputState.value = emptyList()
    }

    // ১. টিসিপি পোর্ট স্ক্যানার (TCP Port Scanner)
    fun scanPorts(targetHost: String) {
        viewModelScope.launch(Dispatchers.IO) {
            _isLoading.value = true
            clearLog()
            log("[+] Starting TCP Port Scan on $targetHost...")
            val commonPorts = listOf(21, 22, 80, 443, 8080, 3306, 8443)
            
            for (port in commonPorts) {
                try {
                    val socket = Socket()
                    socket.connect(InetSocketAddress(targetHost, port), 400) // ৪০০ms টাইমআউট
                    log("[OPEN] Port $port/TCP is OPEN")
                    socket.close()
                } catch (e: Exception) {
                    log("[CLOSED] Port $port/TCP is CLOSED/FILTERED")
                }
            }
            log("[+] Scan Complete.")
            _isLoading.value = false
        }
    }

    // ২. পিং ও ডিএনএস লুকআপ (Ping & DNS Lookup)
    fun pingAndDns(domain: String) {
        viewModelScope.launch(Dispatchers.IO) {
            _isLoading.value = true
            clearLog()
            log("[+] Resolving DNS for: $domain")
            try {
                val addresses = InetAddress.getAllByName(domain)
                for (addr in addresses) {
                    log(" -> Resolved IP: ${addr.hostAddress}")
                    val reachable = addr.isReachable(2000)
                    log(" -> Latency Check: ${if (reachable) "SUCCESS (Reachable)" else "FAILED (Unreachable)"}")
                }
            } catch (e: Exception) {
                log("[!] DNS Lookup Error: ${e.localizedMessage}")
            }
            _isLoading.value = false
        }
    }

    // ৩. হ্যাশ জেনারেটর (Hash Generator: MD5 & SHA-256)
    fun generateHashes(inputText: String) {
        viewModelScope.launch(Dispatchers.Default) {
            _isLoading.value = true
            clearLog()
            log("[+] Generating Cryptographic Hashes for input...")
            
            val md5 = MessageDigest.getInstance("MD5").digest(inputText.toByteArray())
                .joinToString("") { "%02x".format(it) }
            val sha256 = MessageDigest.getInstance("SHA-256").digest(inputText.toByteArray())
                .joinToString("") { "%02x".format(it) }

            log(" -> MD5: $md5")
            log(" -> SHA-256: $sha256")
            _isLoading.value = false
        }
    }

    // ৪. Base64 & URL এনকোডার/ডিকোডার
    fun processBase64(inputText: String, encode: Boolean) {
        viewModelScope.launch(Dispatchers.Default) {
            _isLoading.value = true
            clearLog()
            try {
                if (encode) {
                    val encoded = Base64.getEncoder().encodeToString(inputText.toByteArray())
                    log("[+] Base64 Encoded Result:")
                    log(encoded)
                } else {
                    val decoded = String(Base64.getDecoder().decode(inputText))
                    log("[+] Base64 Decoded Result:")
                    log(decoded)
                }
            } catch (e: Exception) {
                log("[!] Base64 Processing Error: Invalid Format")
            }
            _isLoading.value = false
        }
    }

    // ৫. HTTP হেডার ও WAF চেকার
    fun checkHttpHeaders(urlStr: String) {
        viewModelScope.launch(Dispatchers.IO) {
            _isLoading.value = true
            clearLog()
            log("[+] Fetching HTTP Headers for: $urlStr")
            try {
                val url = if (!urlStr.startsWith("http")) URL("https://$urlStr") else URL(urlStr)
                val conn = url.openConnection() as HttpURLConnection
                conn.requestMethod = "GET"
                conn.connectTimeout = 3000
                conn.readTimeout = 3000

                val serverHeader = conn.getHeaderField("Server") ?: "Unknown"
                log(" -> Server Header: $serverHeader")

                // WAF ফিনগারপ্রিন্টিং চেক
                val isWafDetected = serverHeader.contains("cloudflare", ignoreCase = true) ||
                        serverHeader.contains("akamai", ignoreCase = true) ||
                        conn.getHeaderField("X-CDN") != null

                log(" -> WAF Security Presence: ${if (isWafDetected) "DETECTED (Protected)" else "NOT DETECTED / GENERIC"}")

                conn.headerFields.forEach { (key, value) ->
                    if (key != null) log(" -> $key: ${value.joinToString(",")}")
                }
            } catch (e: Exception) {
                log("[!] HTTP Check Error: ${e.localizedMessage}")
            }
            _isLoading.value = false
        }
    }
}

// --------------------------------------------------------------------
// [UI DASHBOARD: NEON GLASSMORPHISM]
// --------------------------------------------------------------------
@Composable
fun NetSecSentinelApp(viewModel: SecurityEngineViewModel = androidx.lifecycle.viewmodel.compose.viewModel()) {
    var targetInput by remember { mutableStateOf("example.com") }
    val outputList by viewModel.outputState.collectAsState()
    val isLoading by viewModel.isLoading.collectAsState()

    Surface(
        modifier = Modifier.fillMaxSize(),
        color = DarkBackground
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp)
        ) {
            // শিরোনাম
            Text(
                text = "⚡ NETSEC SENTINEL",
                fontSize = 22.sp,
                fontWeight = FontWeight.Bold,
                color = NeonCyan,
                fontFamily = FontFamily.Monospace,
                modifier = Modifier.padding(bottom = 12.dp)
            )

            // ইনপুট ফিল্ড
            OutlinedTextField(
                value = targetInput,
                onValueChange = { targetInput = it },
                label = { Text("Target IP / Domain / String", color = NeonGreen) },
                singleLine = true,
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = NeonGreen,
                    unfocusedBorderColor = BorderColor,
                    focusedTextColor = Color.White,
                    unfocusedTextColor = Color.White
                ),
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 12.dp)
            )

            // ইউটিলিটি টুলস বোতাম
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    GlassButton("TCP Port Scan", NeonGreen, Modifier.weight(1f)) {
                        viewModel.scanPorts(targetInput)
                    }
                    GlassButton("Ping & DNS", NeonCyan, Modifier.weight(1f)) {
                        viewModel.pingAndDns(targetInput)
                    }
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    GlassButton("Hash Generator", NeonPink, Modifier.weight(1f)) {
                        viewModel.generateHashes(targetInput)
                    }
                    GlassButton("HTTP / WAF", NeonCyan, Modifier.weight(1f)) {
                        viewModel.checkHttpHeaders(targetInput)
                    }
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    GlassButton("Base64 Encode", NeonGreen, Modifier.weight(1f)) {
                        viewModel.processBase64(targetInput, true)
                    }
                    GlassButton("Base64 Decode", NeonPink, Modifier.weight(1f)) {
                        viewModel.processBase64(targetInput, false)
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // রেন্ডার এরিয়া: রেজাল্ট আউটপুট কার্ড উইথ স্পিনার
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f)
                    .background(GlassCardBackground, RoundedCornerShape(12.dp))
                    .border(1.dp, BorderColor, RoundedCornerShape(12.dp))
                    .padding(12.dp)
            ) {
                if (isLoading) {
                    CircularProgressIndicator(
                        color = NeonGreen,
                        modifier = Modifier.align(Alignment.Center)
                    )
                } else if (outputList.isEmpty()) {
                    Text(
                        text = "> System Ready. Select an action to execute diagnostic analysis.",
                        color = Color.Gray,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 13.sp
                    )
                } else {
                    LazyColumn {
                        items(outputList) { line ->
                            Text(
                                text = line,
                                color = when {
                                    line.startsWith("[OPEN]") -> NeonGreen
                                    line.startsWith("[!]") -> NeonPink
                                    line.startsWith("[+]") -> NeonCyan
                                    else -> Color.LightGray
                                },
                                fontFamily = FontFamily.Monospace,
                                fontSize = 12.sp,
                                modifier = Modifier.padding(vertical = 2.dp)
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun GlassButton(text: String, accentColor: Color, modifier: Modifier = Modifier, onClick: () -> Unit) {
    Button(
        onClick = onClick,
        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF161B22)),
        shape = RoundedCornerShape(8.dp),
        modifier = modifier.border(1.dp, accentColor.copy(alpha = 0.6f), RoundedCornerShape(8.dp))
    ) {
        Text(
            text = text,
            color = accentColor,
            fontSize = 11.sp,
            fontWeight = FontWeight.SemiBold,
            fontFamily = FontFamily.Monospace,
            maxLines = 1
        )
    }
}
