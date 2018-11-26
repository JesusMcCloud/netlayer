package org.berndpruenster.netlayer.tor.demo

import org.berndpruenster.netlayer.tor.*
import java.io.BufferedReader
import java.io.InputStreamReader
import java.util.*
import kotlin.concurrent.thread


fun main(args: Array<String>) {

    // null authentication
    Tor.default = ExternalTor(9151)

    // password authentication
    //Tor.default = ExternalTor(9151, "password")

    // cookie authentication
    //Tor.default = ExternalTor(9151, File("/path/to/tor/control_auth_cookie"))

    // secure cookie authentication
    //Tor.default = ExternalTor(9151, File("/path/to/tor//control_auth_cookie"), true)

    val server = HiddenServiceSocket(10025,"/tmp/hiddenservicetest")
    server.addReadyListener { socket ->
        System.err.println("Hidden Service socket is ready")

        // create a simple hidden service
        thread(name = "HiddenService") {
            System.err.println("HiddenService is about ready")
            BufferedReader(InputStreamReader(socket.accept().getInputStream())).use {
                System.err.println("HiddenService received: \"${it.readLine()}\"")
            }
        }

        // talk to the newly created hidden service
        thread(name="connectToHiddenService") {
            try {
                // allow tor a few seconds to broadly publish the service
                Thread.sleep(25000)

                println("Contacting the hidden service...")
                val externalSocket = ExternalTorSocket(9150, socket.serviceName, 10025)
                externalSocket.outputStream.write("Hello Tor\n".toByteArray())
                println("[Contacting the hidden service...]done")

                // wait for the hidden service thread to print to System.out
                Thread.sleep(2000)
            } catch (e: Exception) {
                e.printStackTrace()
            } finally {
                System.exit(0)
            }
        }
    }

    System.err.println("It will take some time for the HS to be reachable (up to 40 seconds). You will be notified about this")
    Scanner(System.`in`).nextLine()
}
