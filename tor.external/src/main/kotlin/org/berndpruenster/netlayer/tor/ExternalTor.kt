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
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.random.Random

class ExternalTor : Tor {
    val EVENTS = listOf("CIRC", "WARN", "ERR")

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

    /**
     * 3.24. AUTHCHALLENGE
     *
     * The syntax is: "AUTHCHALLENGE" SP "SAFECOOKIE" SP ClientNonce CRLF
     *
     * ClientNonce = 2*HEXDIG / QuotedString
     *
     * This command is used to begin the authentication routine for the SAFECOOKIE
     * method of authentication.
     *
     * If the server accepts the command, the server reply format is: "250
     * AUTHCHALLENGE" SP "SERVERHASH=" ServerHash SP "SERVERNONCE=" ServerNonce CRLF
     *
     * ServerHash = 64*64HEXDIG ServerNonce = 64*64HEXDIG
     *
     * The ClientNonce, ServerHash, and ServerNonce values are encoded/decoded in
     * the same way as the argument passed to the AUTHENTICATE command. ServerNonce
     * MUST be 32 bytes long.
     *
     * ServerHash is computed as: HMAC-SHA256("Tor safe cookie authentication
     * server-to-controller hash", CookieString | ClientNonce | ServerNonce) (with
     * the HMAC key as its first argument)
     *
     * After a controller sends a successful AUTHCHALLENGE command, the next command
     * sent on the connection must be an AUTHENTICATE command, and the only
     * authentication string which that AUTHENTICATE command will accept is:
     * HMAC-SHA256("Tor safe cookie authentication controller-to-server hash",
     * CookieString | ClientNonce | ServerNonce)
     *
     * [Unlike other commands besides AUTHENTICATE, AUTHCHALLENGE may be used (but
     * only once!) before AUTHENTICATE.]
     *
     * [AUTHCHALLENGE was added in Tor 0.2.3.13-alpha.]
     *
     * @throws IOException
     */
    private class SafeCookieAuthenticator(private val cookieFile: File) : Authenticator() {
        override fun authenticate(controlConnection: TorController) {
            // create client nonce
            val clientNonce = Random.Default.nextBytes(32)
            val result = controlConnection.authChallenge(clientNonce)

            // check if server knows the contents of the cookie
            val keySpec = SecretKeySpec("Tor safe cookie authentication server-to-controller hash".toByteArray(), "HmacSHA256")
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(keySpec)
            try {
                var cookie = cookieFile.readBytes()
                mac.update(cookie)
                mac.update(clientNonce)
                mac.update(result.serverNonce)
                val serverHash = mac.doFinal()
                if(!serverHash.contentEquals(result.serverHash))
                    throw Exception("Tor Safecookie authentication failed: Serverhash does not match computed hash")

                // calculate authentication string
                val keySpec = SecretKeySpec("Tor safe cookie authentication controller-to-server hash".toByteArray(), "HmacSHA256")
                mac.init(keySpec)
                mac.update(cookie)
                mac.update(clientNonce)
                mac.update(result.serverNonce)
                controlConnection.authenticate(mac.doFinal())
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
    constructor(controlPort: Int, password: String) {
        connect(controlPort, PasswordAuthenticator(password))
    }

    @Throws(TorCtlException::class)
    constructor(controlPort: Int, cookieFile: File, useSafeCookieAuthentication: Boolean = false) {
        if(useSafeCookieAuthentication)
            connect(controlPort, SafeCookieAuthenticator(cookieFile))
        else
            connect(controlPort, CookieAuthenticator(cookieFile))
    }

    private fun connect(controlPort: Int, authenticator: Authenticator) {

        // connect to controlPort
        val sock = Socket(LOCAL_IP, controlPort)

        // Open a control connection and authenticate using the cookie file
        torController = TorController(sock)

        // authenticate
        authenticator.authenticate(torController)

        torController.setEventHandler(eventHandler)
        torController.setEvents(EVENTS)

        control = Control(torController)
    }

    override fun preprocessHsDirName(hsDirName: String): File {
        return File(hsDirName)
    }

    override fun shutdown() {
        synchronized(control) {
            // unpublish hidden services
            while(activeHiddenServices.isNotEmpty())
                unpublishHiddenService(activeHiddenServices[0])

            // disconnect from controlPort
        }
    }
}

class ExternalTorSocket
@JvmOverloads constructor(proxyPort: Int, private val destination: String, port: Int, streamID: String? = null) :
        SocksSocket(Tor.getProxy(proxyPort, streamID), destination, port) {
    override fun getRemoteSocketAddress(): SocketAddress = HiddenServiceSocketAddress(destination, port)
}

class ExternalHiddenServiceSocket(localPort: Int) : ServerSocket(localPort, 50, InetAddress.getLoopbackAddress())