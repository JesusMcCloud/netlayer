/*
Copyright 2017, Bernd Prünster <mail@berndpruenster.org>
This file is part of of the unofficial Java-Tor-bindings.

Licensed under the EUPL, Version 1.1 or - as soon they will be approved by the
European Commission - subsequent versions of the EUPL (the "Licence"); You may
not use this work except in compliance with the Licence. You may obtain a copy
of the Licence at: http://joinup.ec.europa.eu/software/page/eupl

Unless required by applicable law or agreed to in writing, software distributed
under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
specific language governing permissions and limitations under the Licence.

This project includes components developed by third parties and provided under
various open source licenses (www.opensource.org).
*/
package org.berndpruenster.netlayer.tor

import com.runjva.sourceforge.jsocks.protocol.SocksSocket
import java.net.Socket
import java.net.InetAddress
import java.net.ServerSocket
import java.net.SocketAddress
import java.io.File

internal const val LOCAL_IP = "127.0.0.1"

class ExternalTor : Tor {
    val EVENTS = listOf("CIRC", "WARN", "ERR")
    private lateinit var ctrlCon: TorController

    private abstract class Authenticator {
        abstract fun authenticate(controlConnection: TorController)
    }

    private class NullAuthenticator : Authenticator() {
        override fun authenticate(controlConnection: TorController) {
            controlConnection.authenticate(ByteArray(0))
        }
    }

    private class PasswordAuthenticator(private val password: String) : Authenticator() {
        override fun authenticate(controlConnection: TorController) {
            controlConnection.authenticate(password.toByteArray())
        }
    }

    private class CookieAuthenticator(private val cookieFile: File) : Authenticator() {
        override fun authenticate(controlConnection: TorController) {
            var cookie: ByteArray?
            try {
                cookie = cookieFile.readBytes()
                controlConnection.authenticate(cookie)
            } catch (e: Exception) {
                e.printStackTrace()
                throw e
            }
        }
    }

    @Throws(TorCtlException::class)
    constructor(controlPort: Int) {
        connect(controlPort, NullAuthenticator())
    }

    @Throws(TorCtlException::class)
    constructor(controlPort: Int, cookieFile: File) {
        connect(controlPort, CookieAuthenticator(cookieFile))
    }

    @Throws(TorCtlException::class)
    constructor(controlPort: Int, password: String) {
        connect(controlPort, PasswordAuthenticator(password))
    }

    private fun connect(controlPort: Int, authenticator: Authenticator) {

        // connect to controlPort
        val sock = Socket(LOCAL_IP, controlPort)

        // Open a control connection and authenticate using the cookie file
        ctrlCon = TorController(sock)

        // authenticate
        authenticator.authenticate(ctrlCon)

        ctrlCon.setEventHandler(eventHandler)
        ctrlCon.setEvents(EVENTS)

        control = Control(ctrlCon);
    }

	
    override fun publishHiddenService(hsDirName: String, hiddenServicePort: Int, localPort: Int): HsContainer {
        return HsContainer(ctrlCon.createHiddenService(hiddenServicePort), eventHandler)
    }

    override fun unpublishHiddenService(hsDir: String) {
        ctrlCon.destroyHiddenService(hsDir)
    }
	
    override fun shutdown() {
        // disconnect from controlPort
    }
}

class ExternalTorSocket
@JvmOverloads constructor(proxyPort: Int, private val destination: String, port: Int, streamID: String? = null) :
        SocksSocket(Tor.getProxy(proxyPort, streamID), destination, port) {
    override fun getRemoteSocketAddress(): SocketAddress = HiddenServiceSocketAddress(destination, port)
}

class ExternalHiddenServiceSocket(localPort: Int) : ServerSocket(localPort, 50, InetAddress.getLoopbackAddress())