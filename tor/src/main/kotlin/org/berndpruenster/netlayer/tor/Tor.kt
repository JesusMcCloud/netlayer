/*
Copyright (c) 2016, 2017 Bernd Prünster
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


 Copyright (c) 2014-2015 Microsoft Open Technologies, Inc.
 Copyright (C) 2011-2014 Sublime Software Ltd

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
*/

package org.berndpruenster.netlayer.tor

import com.runjva.sourceforge.jsocks.protocol.Socks5Proxy
import mu.KLogger
import mu.KotlinLogging
import net.freehaven.tor.control.ConfigEntry
import net.freehaven.tor.control.TorControlConnection
import java.io.*
import java.math.BigInteger
import java.net.Socket
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermission
import java.security.MessageDigest

/**
 * This class began life as TorPlugin from the Briar Project
 */


const val LOCAL_IP = "127.0.0.1"
private const val LOCAL_ADDR_FRAGMENT = "\"" + LOCAL_IP + ":"
private const val NET_LISTENERS_SOCKS = "net/listeners/socks"

private const val STATUS_BOOTSTRAPPED = "status/bootstrap-phase"
private const val DISABLE_NETWORK = "DisableNetwork"

val logger = try {
    KotlinLogging.logger { }
} catch (e: Throwable) {
    System.err.println(e); null
}


class TorCtlException(message: String? = null, cause: Throwable? = null) : Throwable(message, cause)

class TraceStream(logger : KLogger) : PrintWriter(Stream(logger), true) {
    class Stream : OutputStream {
        private val logger : KLogger

        constructor(logger: KLogger) {
            this.logger = logger
        }

        override fun write(p0: Int) {
        }

        override fun write(cbuf: ByteArray, off: Int, len: Int) {
            if(!logger.isTraceEnabled) return
            synchronized(logger) {
                var message = String(cbuf.copyOfRange(off, off + len))
                message.filterNot { it -> it == '\r' }
                message.split(Regex("\\n", RegexOption.MULTILINE)).forEach {
                    if(it.isNotEmpty()) logger.trace(it)
                }
                flush()
            }
        }
    }

}

class TorController : TorControlConnection {

    val bootstrapped: Boolean
        get() = getInfo(STATUS_BOOTSTRAPPED)?.contains("PROGRESS=100") ?: false

    private val socket: Socket

    constructor(socket: Socket) : super(socket) {
        this.socket = socket

        if(null != logger)
            super.setDebugging(TraceStream(logger))
    }

    fun shutdown() {
        socket.use {
            logger?.debug("Stopping Tor")
            setConf(DISABLE_NETWORK, "1")
            shutdownTor("TERM")
        }
    }

    fun enableNetwork() {
        setConf(DISABLE_NETWORK, "0")
    }

}

class Control(private val con: TorController) {

    companion object {
        @JvmStatic
        private val EVENTS_HS = listOf("CIRC", "ORCONN", "INFO", "NOTICE", "WARN", "ERR", "HS_DESC", "HS_DESC_CONTENT")
    }

    internal val proxyPort = parsePort()

    internal var running = true
        private set

    fun shutdown() {
        synchronized(running) {
            if (!running) return
            running = false
            con.shutdown()
        }
    }


    private fun parsePort(): Int {
        // This returns a set of space delimited quoted strings which could be
        // Ipv4, Ipv6 or unix sockets
        val socksIpPorts = con.getInfo(NET_LISTENERS_SOCKS)?.split(" ")

        socksIpPorts?.filter { it.contains(LOCAL_ADDR_FRAGMENT) }?.forEach {
            return Integer.parseInt(it.substring(it.lastIndexOf(":") + 1, it.length - 1))
        }
        throw IOException("No IPv4 localhost binding available!")
    }

    fun enableHiddenServiceEvents() {
        con.setEvents(EVENTS_HS)
    }

    fun hsAvailable(onionUrl: String): Boolean = con.isHSAvailable(onionUrl.substring(0, onionUrl.indexOf(".")))


}

data class HsContainer(val hostname: String, val handler: TorEventHandler)


abstract class Tor @Throws(TorCtlException::class) protected constructor() {

    protected val TOTAL_SEC_PER_STARTUP = 4 * 60
    protected val TRIES_PER_STARTUP = 5

    protected val eventHandler: TorEventHandler = TorEventHandler()
    lateinit var control: Control

    protected lateinit var torController: TorController
    protected val activeHiddenServices = ArrayList<String>()

    companion object {

        @JvmStatic
        var default: Tor? = null

        internal fun clear() {
            default = null
        }


        @Throws(TorCtlException::class)
        @JvmStatic
        @JvmOverloads
        fun getProxy(proxyPort: Int, streamID: String? = null): Socks5Proxy {
            val proxy: Socks5Proxy
            try {
                proxy = Socks5Proxy(LOCAL_IP, proxyPort)
            } catch (e: IOException) {
                throw TorCtlException(cause = e)
            }
            proxy.resolveAddrLocally(false)
            streamID?.let {
                val hash: ByteArray
                val authValue = BigInteger(MessageDigest.getInstance("SHA-256").digest(streamID.toByteArray())).toString(
                        26)
                hash = authValue.toByteArray()

                proxy.setAuthenticationMethod(2, { _, proxySocket ->
                    logger?.debug("using Stream $authValue")

                    val out = proxySocket.getOutputStream()
                    out.write(byteArrayOf(1.toByte(), hash.size.toByte()))
                    out.write(hash)
                    out.write(byteArrayOf(1.toByte(), 0.toByte()))
                    out.flush()
                    val status = ByteArray(2)
                    proxySocket.getInputStream().read(status)
                    if (status[1] != 0.toByte()) {
                        throw IOException("auth error: " + status[1])
                    }
                    arrayOf(proxySocket.getInputStream(), out)
                })
            }
            return proxy

        }
    }

    @Throws(TorCtlException::class)
    @JvmOverloads
    fun getProxy(streamID: String? = null): Socks5Proxy = Tor.getProxy(control.proxyPort, streamID)

    abstract fun preprocessHsDirName(hsDirName: String) : File

    /**
     * Publishes a hidden service
     *
     * @param hiddenServicePort
     *          The port that the hidden service will accept connections on
     * @param localPort
     *          The local port that the hidden service will relay connections to
     * @return The hidden service's onion address in the form X.onion.
     * @throws java.io.IOException
     *           - File errors
     * @throws TorCtlException
     */
    @Throws(IOException::class, TorCtlException::class)
    fun publishHiddenService(hsDirName: String, hiddenServicePort: Int, localPort: Int): HsContainer {

        val hostnameFile = File(preprocessHsDirName(hsDirName), "hostname")
        val keyFile = File(preprocessHsDirName(hsDirName), "private_key")

        val result: TorControlConnection.CreateHiddenServiceResult

        control.enableHiddenServiceEvents()

        if(keyFile.exists()) {
            // if the service has already been started once, we reuse the data
            result = torController.createHiddenService(hiddenServicePort, localPort, keyFile.readText())
        } else {
            // else, we create a fresh service with a fresh key
            result = torController.createHiddenService(hiddenServicePort, localPort)

            // and while we are at it, we persist the hs information for future use
            if (!(hostnameFile.parentFile.exists() || hostnameFile.parentFile.mkdirs())) {
                throw  TorCtlException("Could not create hostnameFile parent directory")
            }

            if (!(hostnameFile.exists() || hostnameFile.createNewFile())) {
                throw  TorCtlException("Could not create hostnameFile")
            }

            if (!(keyFile.exists() || keyFile.createNewFile())) {
                throw  TorCtlException("Could not create keyFile")
            }

            // Thanks, Ubuntu!
            try {
                if (OsType.current.isUnixoid()) {
                    val perms = mutableSetOf(PosixFilePermission.OWNER_READ,
                            PosixFilePermission.OWNER_WRITE,
                            PosixFilePermission.OWNER_EXECUTE)
                    Files.setPosixFilePermissions(hostnameFile.parentFile.toPath(), perms)
                }
            } catch (e: Exception) {
                logger?.error("could not set permissions, hidden service $hsDirName will most probably not work", e)
            }

            hostnameFile.appendText(result.serviceID + ".onion")
            keyFile.appendText(result.privateKey)
        }

        // memorize service in case of ungraceful shutdown
        val hostname = result.serviceID+".onion"
        activeHiddenServices.add(hostname)
        return HsContainer(hostname, eventHandler)
    }

    @Throws(TorCtlException::class, IOException::class)
    fun unpublishHiddenService(serviceName: String) {
        torController.destroyHiddenService(serviceName.replace(Regex("\\.onion$"), ""))

        activeHiddenServices.remove(serviceName)
    }

    fun isHiddenServiceAvailable(onionUrl: String): Boolean = control.hsAvailable(onionUrl)

    abstract fun shutdown()
}
