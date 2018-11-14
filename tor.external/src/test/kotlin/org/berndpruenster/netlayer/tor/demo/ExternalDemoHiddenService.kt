package org.berndpruenster.netlayer.tor.demo

import org.berndpruenster.netlayer.tor.*
import java.io.File
import java.io.BufferedReader
import java.io.InputStreamReader
import kotlin.concurrent.thread


fun main(args: Array<String>) {

	Tor.default = ExternalTor(9151, File("/path/to/tor/control_auth_cookie"))

	var server = HiddenServiceSocket(10025)
    
	// wait for the service to be published
	Thread.sleep(25000)

	// create simple hidden service service
	thread { BufferedReader(InputStreamReader(server.accept().getInputStream())).use { println(it.readLine()) } }

	// talk to the newly created hidden service
	ExternalTorSocket(9150, server.serviceName + ".onion", 10025).outputStream.write("Hello Tor\n".toByteArray())
}
