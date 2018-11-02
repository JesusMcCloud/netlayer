package org.berndpruenster.netlayer.tor.demo

import org.berndpruenster.netlayer.tor.ExternalHiddenServiceSocket
import org.berndpruenster.netlayer.tor.ExternalTorSocket
import java.io.BufferedReader
import java.io.InputStreamReader
import kotlin.concurrent.thread

fun main(args: Array<String>) {

    val sock = ExternalTorSocket(34465, "google.com", 443)
    val hsName = "x4hqvjg6pogtujst.onion"
    val server = ExternalHiddenServiceSocket(10024)
    thread {
        BufferedReader(InputStreamReader(server.accept().getInputStream())).use { println(it.readLine()) }
    }
    ExternalTorSocket(34465, hsName, 10024).outputStream.write("Hello Tor\n".toByteArray())

}