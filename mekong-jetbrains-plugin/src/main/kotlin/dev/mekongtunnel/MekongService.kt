package dev.mekongtunnel

import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.components.Service
import java.io.File
import java.io.OutputStream
import java.net.HttpURLConnection
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.net.URI
import java.net.URL
import java.nio.file.*
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors

@Service(Service.Level.APP)
class MekongService {

    companion object {
        fun getInstance(): MekongService =
            ApplicationManager.getApplication().getService(MekongService::class.java)
    }

    // ── State ─────────────────────────────────────────────────────────────────
    var isRunning     = false
    var publicUrl: String? = null
    var tunnelPort: Int?   = null
    var isLiveRunning = false
    var livePort: Int?     = null

    private var tunnelProcess:    Process?          = null
    private var liveServerThread: LiveServerThread? = null
    private val listeners = mutableListOf<() -> Unit>()

    // ── Listeners ─────────────────────────────────────────────────────────────
    fun addListener(l: () -> Unit)    { listeners.add(l) }
    fun removeListener(l: () -> Unit) { listeners.remove(l) }
    fun notifyState() = ApplicationManager.getApplication().invokeLater { listeners.forEach { it() } }

    // ── Mekong binary ─────────────────────────────────────────────────────────
    fun findMekong(): String? {
        val isWin = System.getProperty("os.name").lowercase().contains("win")
        try {
            val result = Runtime.getRuntime().exec(if (isWin) arrayOf("where","mekong") else arrayOf("which","mekong"))
                .inputStream.bufferedReader().readLine()?.trim()
            if (!result.isNullOrBlank() && File(result).exists()) return result
        } catch (_: Exception) {}
        val home = System.getProperty("user.home")
        val candidates = if (isWin) {
            val localAppData = System.getenv("LOCALAPPDATA") ?: "$home\\AppData\\Local"
            listOf(
                "$localAppData\\Programs\\mekong\\mekong.exe",
                "$localAppData\\mekong.exe",
                "$home\\.local\\bin\\mekong.exe",
            )
        } else {
            listOf("/usr/local/bin/mekong", "$home/.local/bin/mekong", "$home/bin/mekong",
                "/usr/bin/mekong", "/opt/homebrew/bin/mekong")
        }
        return candidates.firstOrNull { File(it).exists() }
    }

    // ── Auth ──────────────────────────────────────────────────────────────────
    private fun readConfig(): String? = try {
        File(System.getProperty("user.home"), ".mekong/config.json").takeIf { it.exists() }?.readText()
    } catch (_: Exception) { null }

    fun readSavedToken(): String? =
        readConfig()?.let { Regex(""""token"\s*:\s*"([^"]+)"""").find(it)?.groupValues?.get(1) }

    fun readSavedEmail(): String? =
        readConfig()?.let { Regex(""""email"\s*:\s*"([^"]+)"""").find(it)?.groupValues?.get(1) }

    fun isLoggedIn() = readSavedToken() != null

    fun readSavedPlan(): String? {
        return try {
            val token = readSavedToken() ?: return null
            val body  = httpGet("https://api.mekongtunnel.dev/api/auth/token-info",
                                mapOf("Authorization" to "Bearer $token")) ?: return null
            Regex(""""plan"\s*:\s*"([^"]+)"""").find(body)?.groupValues?.get(1)
        } catch (_: Exception) { null }
    }

    /** Device-flow login — opens browser, polls for approval, saves token. */
    fun startDeviceLogin(onLog: (String) -> Unit, onDone: () -> Unit) {
        ApplicationManager.getApplication().executeOnPooledThread {
            try {
                onLog("Connecting to mekongtunnel.dev…")
                val createBody = httpPost("https://api.mekongtunnel.dev/api/cli/device", "")
                    ?: run { onLog("ERROR: Could not reach login server"); return@executeOnPooledThread }

                val sessionId = Regex(""""session_id"\s*:\s*"([^"]+)"""").find(createBody)?.groupValues?.get(1)
                    ?: run { onLog("ERROR: Bad response from server"); return@executeOnPooledThread }
                val loginUrl  = Regex(""""login_url"\s*:\s*"([^"]+)"""").find(createBody)?.groupValues?.get(1)
                    ?: "https://mekongtunnel.dev/cli-auth?session=$sessionId"
                val pollSecs  = Regex(""""poll_interval"\s*:\s*(\d+)""").find(createBody)?.groupValues?.get(1)?.toLongOrNull() ?: 3L

                onLog("Opening browser — authorize in the browser window")
                com.intellij.ide.BrowserUtil.browse(loginUrl)

                val deadline = System.currentTimeMillis() + 5 * 60_000L
                while (System.currentTimeMillis() < deadline) {
                    Thread.sleep(pollSecs * 1000)
                    val pollBody = httpGet("https://api.mekongtunnel.dev/api/cli/device?session_id=$sessionId") ?: continue
                    val status   = Regex(""""status"\s*:\s*"([^"]+)"""").find(pollBody)?.groupValues?.get(1)
                    val token    = Regex(""""token"\s*:\s*"([^"]+)"""").find(pollBody)?.groupValues?.get(1)

                    when (status) {
                        "approved" -> {
                            if (token.isNullOrBlank()) { onLog("ERROR: Session approved but no token returned"); return@executeOnPooledThread }
                            // Fetch email + plan
                            val infoBody = httpGet("https://api.mekongtunnel.dev/api/auth/token-info",
                                                   mapOf("Authorization" to "Bearer $token"))
                            val email  = infoBody?.let { Regex(""""email"\s*:\s*"([^"]+)"""").find(it)?.groupValues?.get(1) } ?: ""
                            val userId = infoBody?.let { Regex(""""id"\s*:\s*"([^"]+)"""").find(it)?.groupValues?.get(1) }   ?: ""
                            // Save config
                            val cfgDir = File(System.getProperty("user.home"), ".mekong")
                            cfgDir.mkdirs()
                            val json = buildString {
                                append("{\n  \"token\": \"$token\"")
                                if (email.isNotBlank())  append(",\n  \"email\": \"$email\"")
                                if (userId.isNotBlank()) append(",\n  \"user_id\": \"$userId\"")
                                append("\n}\n")
                            }
                            File(cfgDir, "config.json").writeText(json)
                            onLog("Logged in" + if (email.isNotBlank()) " as $email" else "")
                            notifyState()
                            ApplicationManager.getApplication().invokeLater { onDone() }
                            return@executeOnPooledThread
                        }
                        "expired" -> { onLog("Session expired — click Log in to try again"); return@executeOnPooledThread }
                        else -> { /* pending — keep polling */ }
                    }
                }
                onLog("Login timed out — click Log in to try again")
            } catch (e: Exception) { onLog("Login error: ${e.message}") }
        }
    }

    // ── HTTP helpers ──────────────────────────────────────────────────────────
    private fun httpPost(url: String, body: String, headers: Map<String, String> = emptyMap()): String? = try {
        val conn = URI(url).toURL().openConnection() as HttpURLConnection
        conn.requestMethod = "POST"
        conn.doOutput = true
        conn.connectTimeout = 10_000; conn.readTimeout = 10_000
        conn.setRequestProperty("Content-Type", "application/json")
        headers.forEach { (k, v) -> conn.setRequestProperty(k, v) }
        conn.outputStream.use { it.write(body.toByteArray()) }
        if (conn.responseCode in 200..299) conn.inputStream.bufferedReader().readText() else null
    } catch (_: Exception) { null }

    private fun httpGet(url: String, headers: Map<String, String> = emptyMap()): String? = try {
        val conn = URI(url).toURL().openConnection() as HttpURLConnection
        conn.requestMethod = "GET"
        conn.connectTimeout = 10_000; conn.readTimeout = 10_000
        headers.forEach { (k, v) -> conn.setRequestProperty(k, v) }
        if (conn.responseCode in 200..299) conn.inputStream.bufferedReader().readText() else null
    } catch (_: Exception) { null }

    // ── Tunnel ────────────────────────────────────────────────────────────────
    fun startTunnel(port: Int, expire: String?, onLog: (String) -> Unit, onUrl: (String) -> Unit) {
        val bin = findMekong() ?: run { onLog("ERROR: mekong not found — install from mekongtunnel.dev"); return }
        val args = mutableListOf(bin, port.toString())
        if (!expire.isNullOrBlank()) args += listOf("--expire", expire)
        readSavedToken()?.let { args += listOf("--token", it) }
        args += "--no-qr"

        ApplicationManager.getApplication().executeOnPooledThread {
            try {
                val proc = ProcessBuilder(args).redirectErrorStream(true).start()
                tunnelProcess = proc; tunnelPort = port; isRunning = true; notifyState()
                proc.inputStream.bufferedReader().forEachLine { raw ->
                    val line = raw.replace(Regex("\u001B\\[[0-9;]*[mGKHFJA-Za-z]"), "").trim()
                    if (line.isNotEmpty()) onLog(line)
                    if (publicUrl == null) {
                        Regex("https?://[^\\s\\x1b\\]]+").find(line)?.let { m ->
                            publicUrl = m.value.replace(Regex("[^\\w.:/-]"), "")
                            onUrl(publicUrl!!); notifyState()
                        }
                    }
                }
                onLog("Process exited (code ${proc.waitFor()})")
            } catch (e: Exception) { onLog("ERROR: ${e.message}") }
            finally { tunnelProcess = null; publicUrl = null; tunnelPort = null; isRunning = false; notifyState() }
        }
    }

    fun stopTunnel() {
        tunnelProcess?.destroyForcibly()
        tunnelProcess = null; publicUrl = null; tunnelPort = null; isRunning = false; notifyState()
    }

    // ── Live Server ───────────────────────────────────────────────────────────
    fun startLiveServer(rootDir: String, port: Int = 5500, onLog: (String) -> Unit, onReady: (Int) -> Unit) {
        ApplicationManager.getApplication().executeOnPooledThread {
            try {
                val thread = LiveServerThread(File(rootDir), port, onLog)
                liveServerThread = thread
                thread.start()
                isLiveRunning = true; livePort = port; notifyState()
                onLog("Live Server started on http://localhost:$port")
                onLog("Serving: $rootDir")
                onReady(port)
            } catch (e: Exception) {
                onLog("ERROR starting Live Server: ${e.message}")
                isLiveRunning = false; livePort = null; notifyState()
            }
        }
    }

    fun stopLiveServer() {
        liveServerThread?.stopServer()
        liveServerThread = null; isLiveRunning = false; livePort = null; notifyState()
    }

    fun stopAll() { stopTunnel(); stopLiveServer() }
}

// ── Built-in HTTP Live Server ──────────────────────────────────────────────────
class LiveServerThread(
    private val rootDir: File,
    private val port: Int,
    private val onLog: (String) -> Unit,
) : Thread("mekong-live-server") {

    @Volatile private var active = true
    private val sseClients = CopyOnWriteArrayList<OutputStream>()
    private val executor   = Executors.newCachedThreadPool()
    private var serverSocket: ServerSocket? = null

    init { isDaemon = true }

    override fun run() {
        try {
            serverSocket = ServerSocket(port)
            // Start file watcher
            startWatcher()
            while (active && !isInterrupted) {
                val client = serverSocket!!.accept()
                executor.submit { handleClient(client) }
            }
        } catch (_: SocketException) {
            // closed normally
        } catch (e: Exception) {
            onLog("Live Server error: ${e.message}")
        } finally {
            executor.shutdown()
        }
    }

    fun stopServer() {
        active = false
        sseClients.forEach { try { it.close() } catch (_: Exception) {} }
        sseClients.clear()
        try { serverSocket?.close() } catch (_: Exception) {}
        interrupt()
    }

    // ── File watcher ──────────────────────────────────────────────────────────
    private fun startWatcher() {
        val watchThread = Thread(null, {
            try {
                val ws = FileSystems.getDefault().newWatchService()
                Paths.get(rootDir.absolutePath).register(ws,
                    StandardWatchEventKinds.ENTRY_MODIFY,
                    StandardWatchEventKinds.ENTRY_CREATE,
                    StandardWatchEventKinds.ENTRY_DELETE)
                while (active && !isInterrupted) {
                    val key = ws.take()
                    val changed = key.pollEvents()
                        .mapNotNull { (it.context() as? Path)?.toString() }
                        .filter { !it.startsWith(".") }
                    if (changed.isNotEmpty()) {
                        onLog("Changed: ${changed.joinToString(", ")} — reloading")
                        pushReload()
                    }
                    key.reset()
                }
                ws.close()
            } catch (_: InterruptedException) {}
            catch (_: ClosedWatchServiceException) {}
        }, "mekong-live-watcher")
        watchThread.isDaemon = true
        watchThread.start()
    }

    private fun pushReload() {
        val msg = "data: reload\n\n".toByteArray()
        val dead = mutableListOf<OutputStream>()
        sseClients.forEach { out -> try { out.write(msg); out.flush() } catch (_: Exception) { dead.add(out) } }
        sseClients.removeAll(dead.toSet())
    }

    // ── Request handler ───────────────────────────────────────────────────────
    private fun handleClient(socket: Socket) {
        try {
            val input = socket.inputStream.bufferedReader()
            val first = input.readLine()?.trim() ?: return
            val parts = first.split(" ")
            if (parts.size < 2) return
            val path = parts[1].substringBefore("?")
            // consume headers
            while (true) { val l = input.readLine(); if (l.isNullOrBlank()) break }

            if (path == "/__mekong_sse") handleSSE(socket)
            else                          serveFile(socket, path)
        } catch (_: Exception) { try { socket.close() } catch (_: Exception) {} }
    }

    private fun handleSSE(socket: Socket) {
        val out = socket.getOutputStream()
        out.write(
            ("HTTP/1.1 200 OK\r\n" +
            "Content-Type: text/event-stream\r\n" +
            "Cache-Control: no-cache\r\n" +
            "Access-Control-Allow-Origin: *\r\n" +
            "Connection: keep-alive\r\n\r\n").toByteArray()
        )
        out.flush()
        sseClients.add(out)
        try {
            while (active && !socket.isClosed) {
                Thread.sleep(8000)
                out.write(": heartbeat\n\n".toByteArray()); out.flush()
            }
        } catch (_: Exception) {}
        sseClients.remove(out)
        try { socket.close() } catch (_: Exception) {}
    }

    private fun serveFile(socket: Socket, rawPath: String) {
        val out = socket.getOutputStream()
        try {
            val rel  = rawPath.trimStart('/').ifEmpty { "" }
            val file = if (rel.isEmpty()) findDefault(rootDir)
                       else File(rootDir, rel).takeIf { it.exists() && it.isFile }

            if (file == null) {
                val body = "404 Not Found".toByteArray()
                out.write("HTTP/1.1 404 Not Found\r\nContent-Length: ${body.size}\r\n\r\n".toByteArray())
                out.write(body); return
            }

            val ext = file.extension.lowercase()
            val (mime, bytes) = when (ext) {
                "html", "htm"      -> "text/html; charset=utf-8" to injectSSE(file.readText()).toByteArray()
                "md", "markdown"   -> "text/html; charset=utf-8" to renderMarkdown(file).toByteArray()
                else               -> mimeOf(ext) to file.readBytes()
            }
            out.write("HTTP/1.1 200 OK\r\nContent-Type: $mime\r\nContent-Length: ${bytes.size}\r\n\r\n".toByteArray())
            out.write(bytes)
        } finally { out.flush(); try { socket.close() } catch (_: Exception) {} }
    }

    // ── Default file ──────────────────────────────────────────────────────────
    private fun findDefault(dir: File): File? =
        listOf("index.html", "index.htm", "README.md", "readme.md", "Readme.md", "index.md")
            .map { File(dir, it) }.firstOrNull { it.exists() }

    // ── SSE injection ─────────────────────────────────────────────────────────
    private val sseScript = """<script>(function(){var es=new EventSource('/__mekong_sse');es.onmessage=function(e){if(e.data==='reload')location.reload()};es.onerror=function(){setTimeout(function(){location.reload()},2000)}})();</script>"""

    private fun injectSSE(html: String): String =
        if (html.contains("</body>", ignoreCase = true))
            html.replace(Regex("</body>", RegexOption.IGNORE_CASE), "$sseScript</body>")
        else html + sseScript

    // ── Markdown renderer ─────────────────────────────────────────────────────
    private fun renderMarkdown(file: File): String {
        val lines  = file.readText().lines()
        val body   = StringBuilder()
        var inPre  = false
        var inList = false

        for (raw in lines) {
            when {
                raw.startsWith("```") -> {
                    if (inPre) { body.append("</code></pre>\n"); inPre = false }
                    else { closeList(body, inList).also { inList = false }; body.append("<pre><code>"); inPre = true }
                }
                inPre -> body.append(raw.esc() + "\n")
                raw.startsWith("#### ") -> { closeList(body, inList).also { inList = false }; body.append("<h4>${raw.drop(5).inline()}</h4>\n") }
                raw.startsWith("### ")  -> { closeList(body, inList).also { inList = false }; body.append("<h3>${raw.drop(4).inline()}</h3>\n") }
                raw.startsWith("## ")   -> { closeList(body, inList).also { inList = false }; body.append("<h2>${raw.drop(3).inline()}</h2>\n") }
                raw.startsWith("# ")    -> { closeList(body, inList).also { inList = false }; body.append("<h1>${raw.drop(2).inline()}</h1>\n") }
                raw.startsWith("---") || raw.startsWith("===") -> body.append("<hr>\n")
                raw.startsWith("- ") || raw.startsWith("* ") -> {
                    if (!inList) { body.append("<ul>\n"); inList = true }
                    body.append("<li>${raw.drop(2).inline()}</li>\n")
                }
                raw.matches(Regex("^\\d+\\.\\s.*")) -> {
                    if (!inList) { body.append("<ol>\n"); inList = true }
                    body.append("<li>${raw.replace(Regex("^\\d+\\.\\s"), "").inline()}</li>\n")
                }
                raw.startsWith("> ") -> { closeList(body, inList).also { inList = false }; body.append("<blockquote>${raw.drop(2).inline()}</blockquote>\n") }
                raw.isBlank() -> { closeList(body, inList).also { inList = false }; body.append("\n") }
                else -> { closeList(body, inList).also { inList = false }; body.append("<p>${raw.inline()}</p>\n") }
            }
        }
        if (inList) body.append("</ul>\n")

        return """<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${file.nameWithoutExtension}</title>
<style>
*{box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:15px;line-height:1.65;max-width:860px;margin:0 auto;padding:32px 24px 64px;background:#0d1117;color:#e6edf3}
h1,h2,h3,h4{color:#f0f6fc;margin-top:24px;margin-bottom:8px}
h1,h2{border-bottom:1px solid #21262d;padding-bottom:8px}
a{color:#58a6ff;text-decoration:none}a:hover{text-decoration:underline}
code{background:#161b22;color:#79c0ff;padding:2px 6px;border-radius:4px;font-family:'Fira Code',monospace;font-size:13px}
pre{background:#161b22;padding:16px;border-radius:8px;overflow-x:auto;border:1px solid #30363d;margin:16px 0}
pre code{background:none;padding:0;color:#e6edf3}
blockquote{border-left:4px solid #3d444d;margin:8px 0;padding:4px 16px;color:#8b9ab3;background:#161b22;border-radius:0 6px 6px 0}
ul,ol{padding-left:24px}li{margin:4px 0}
img{max-width:100%;border-radius:6px;display:block}
table{border-collapse:collapse;width:100%;margin:16px 0}
td,th{border:1px solid #30363d;padding:8px 12px;text-align:left}
th{background:#161b22;font-weight:600}
tr:nth-child(even){background:#161b22}
hr{border:none;border-top:1px solid #21262d;margin:24px 0}
</style></head>
<body>
$body
$sseScript
</body></html>"""
    }

    private fun closeList(sb: StringBuilder, inList: Boolean): StringBuilder {
        if (inList) sb.append("</ul>\n"); return sb
    }

    private fun String.esc() = replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

    private fun String.inline(): String = this.esc()
        .replace(Regex("`([^`]+)`"),           "<code>$1</code>")
        .replace(Regex("\\*\\*([^*]+)\\*\\*"), "<strong>$1</strong>")
        .replace(Regex("__([^_]+)__"),          "<strong>$1</strong>")
        .replace(Regex("\\*([^*]+)\\*"),        "<em>$1</em>")
        .replace(Regex("_([^_]+)_"),            "<em>$1</em>")
        .replace(Regex("~~([^~]+)~~"),           "<del>$1</del>")
        .replace(Regex("!\\[([^]]*)]\\(([^)]+)\\)"), "<img src=\"$2\" alt=\"$1\">")
        .replace(Regex("\\[([^]]+)]\\(([^)]+)\\)"),  "<a href=\"$2\">$1</a>")

    private fun mimeOf(ext: String) = when (ext) {
        "css"  -> "text/css"
        "js"   -> "application/javascript"
        "json" -> "application/json"
        "png"  -> "image/png"
        "jpg","jpeg" -> "image/jpeg"
        "gif"  -> "image/gif"
        "svg"  -> "image/svg+xml"
        "ico"  -> "image/x-icon"
        "woff" -> "font/woff"
        "woff2"-> "font/woff2"
        "ttf"  -> "font/ttf"
        "txt"  -> "text/plain"
        "xml"  -> "application/xml"
        else   -> "application/octet-stream"
    }
}
