package org.berndpruenster.netlayer.tor.demo

import org.berndpruenster.netlayer.tor.ExternalHiddenServiceSocket
import org.berndpruenster.netlayer.tor.ExternalTorSocket
import java.io.BufferedReader
import java.io.InputStreamReader

fun main(args:Array<String>){

    val sock = ExternalTorSocket(34465,"google.com",443)
    val hsName = "x4hqvjg6pogtujst.onion"
    val server = ExternalHiddenServiceSocket(10024)
    Thread({
        BufferedReader(InputStreamReader(
        server.accept().getInputStream())).use { println(it.readLine()) }}).start()
    ExternalTorSocket(34465,hsName,10024).outputStream.write("Hello Tor\n".toByteArray())

}