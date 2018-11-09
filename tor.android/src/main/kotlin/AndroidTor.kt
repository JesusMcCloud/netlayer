package org.berndpruenster.netlayer.tor

import android.content.Context
import android.os.FileObserver
import org.torproject.android.binary.TorResourceInstaller
import java.io.File
import java.io.FileInputStream
import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

private const val TOR_EXEC = "tor"

class AndroidTor @JvmOverloads @Throws(TorCtlException::class) constructor(ctx: Context,
                                                                          workingDirectory: File,
                                                                          bridgeLines: Collection<String>? = null,
                                                                          torrcOverrides: Torrc? = null) : Tor(
        AndroidContext(ctx, workingDirectory, torrcOverrides),
        bridgeLines)


class AndroidContext(ctx: Context, workingDirectory: File, overrides: Torrc?) : TorContext(workingDirectory,
                                                                                           overrides) {
    private val rsrc = TorResourceInstaller(ctx, workingDirectory)

    init {
        if (!rsrc.installResources()) throw IOException("could not extract resources")
    }

    override val pathToRC = "torrc"
    override val pathToTorExecutable = workingDirectory.canonicalPath
    override val processId = android.os.Process.myPid().toString()
    override val torExecutableFileName = "tor"

    override fun generateWriteObserver(file: File) = AndroidWriteObserver(file)

    override fun getByName(fileName: String) = FileInputStream("$workingDirectory/$fileName")

}

class AndroidWriteObserver(file: File) : FileObserver(file.canonicalPath), WriteObserver {

    override fun onEvent(event: Int, path: String?) {
        stopWatching()
        countDownLatch.countDown()
    }

    private val countDownLatch = CountDownLatch(1)
    override fun poll(timeout: Long, unit: TimeUnit) = countDownLatch.await(timeout, unit)


}