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
import mu.KotlinLogging
import net.freehaven.tor.control.ConfigEntry
import java.io.File
import java.io.IOException
import java.math.BigInteger
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermission
import java.security.MessageDigest
import java.util.concurrent.TimeUnit.MILLISECONDS

/**
 * This class began life as TorPlugin from the Briar Project
 */


internal const val LOCAL_IP = "127.0.0.1"
private const val TOTAL_SEC_PER_STARTUP = 4 * 60
private const val TRIES_PER_STARTUP = 5

private const val HS_PORT = "HiddenServicePort"

private const val LOCAL_ADDR_FRAGMENT = "\"" + LOCAL_IP + ":"
private const val HS_DIR = "HiddenServiceDir"


private const val NET_LISTENERS_SOCKS = "net/listeners/socks"


private const val HOSTNAME_TIMEOUT = 30 * 1000                                       // Milliseconds

val logger = try {
    KotlinLogging.logger { }
} catch (e: Throwable) {
    System.err.println(e); null
}


class TorCtlException(message: String? = null, cause: Throwable? = null) : Throwable(message, cause)

private class Control(private val con: TorController) {

    companion object {
        @JvmStatic
        private val EVENTS_HS = listOf("EXTENDED", "CIRC", "ORCONN", "INFO", "NOTICE", "WARN", "ERR", "HS_DESC")

        private const val HS_OPTS = "HiddenServiceOptions"
    }

    internal val proxyPort = parsePort()

    internal var running = true
        private set

    init {
        Runtime.getRuntime().addShutdownHook(Thread({ shutdown() }))
    }


    internal fun shutdown() {
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

    val hiddenServices: List<ConfigEntry> get() = con.getConf(HS_OPTS)
    fun enableHiddenServiceEvents() {
        con.setEvents(EVENTS_HS)
    }

    fun saveConfig(config: List<String>) {
        con.setConf(config)
        con.saveConf()
    }

    fun hsAvailable(onionUrl: String): Boolean = con.isHSAvailable(onionUrl.substring(0, onionUrl.indexOf(".")))


}

internal data class HsContainer(internal val hostname: String, internal val handler: TorEventHandler)


abstract class Tor @Throws(TorCtlException::class) protected constructor(protected val context: TorContext,
                                                                         bridgeLines: Collection<String>? = null) {


    private val eventHandler: TorEventHandler = TorEventHandler()
    private val bridgeConfig: List<String> = bridgeLines?.filter { it.length > 10 } ?: emptyList()
    private val control: Control = try {
        bootstrap()
    } catch (e: Exception) {
        throw TorCtlException(cause = e)
    }
        get() {
            if (!field.running) throw TorCtlException("Tor has already been shutdown!")
            return field
        }


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


    @Throws(InterruptedException::class, IOException::class)
    private fun bootstrap(secondsBeforeTimeOut: Int = TOTAL_SEC_PER_STARTUP,
                          numberOfRetries: Int = TRIES_PER_STARTUP): Control {
        var control: TorController? = null
        try {
            for (retryCount in 1..numberOfRetries) {
                control = context.installAndStartTorOp(bridgeConfig, eventHandler)
                control.enableNetwork()
                // We will check every second to see if boot strapping has
                // finally finished
                for (secondsWaited in 1..secondsBeforeTimeOut) {
                    if (!control.bootstrapped) {
                        Thread.sleep(1000, 0)
                    } else {
                        return Control(control)
                    }
                }

                // Bootstrapping isn't over so we need to restart and try again
                control.shutdown()

                // Experimentally we have found that if a Tor OP has run before and thus
                // has cached descriptors
                // and that when we try to start it again it won't start then deleting
                // the cached data can fix this.
                // But, if there is cached data and things do work then the Tor OP will
                // start faster than it would
                // if we delete everything.
                // So our compromise is that we try to start the Tor OP 'as is' on the
                // first round and after that
                // we delete all the files.
                context.deleteAllFilesButHS()
            }

            throw TorCtlException("Could not setup Tor")


        } finally {
            // Make sure we return the Tor OP in some kind of consistent state,
            // even if it's 'off'.
            if (control?.bootstrapped != true) {
                try {
                    context.deleteAllFilesButHS()
                    control?.shutdown()
                } catch (e: Exception) {
                    logger?.error { e.localizedMessage }
                }
            }
        }
    }

    @Throws(TorCtlException::class)
    @JvmOverloads
    fun getProxy(streamID: String? = null): Socks5Proxy = Tor.getProxy(control.proxyPort, streamID)


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
    internal fun publishHiddenService(hsDirName: String, hiddenServicePort: Int, localPort: Int): HsContainer {
        synchronized(control) {

            val currentHiddenServices = control.hiddenServices

            val hiddenServiceDirectory = context.getHiddenServiceDirectory(hsDirName)

            val config = mutableListOf<String>()

            for (service in currentHiddenServices) {
                if (service.is_default) {
                    continue
                }
                if (service.key == (HS_DIR) && service.value == hiddenServiceDirectory.canonicalPath) {
                    throw TorCtlException("Hidden Service ${hiddenServiceDirectory.canonicalPath} is already published")
                }
                config.add("${service.key} ${service.value}")
            }

            logger?.debug("Creating hidden service $hsDirName")
            val hostnameFile = context.getHostNameFile(hsDirName)

            if (!(hostnameFile.parentFile.exists() || hostnameFile.parentFile.mkdirs())) {
                throw  TorCtlException("Could not create hostnameFile parent directory")
            }

            if (!(hostnameFile.exists() || hostnameFile.createNewFile())) {
                throw  TorCtlException("Could not create hostnameFile")
            }
            // Thanks, Ubuntu!
            try {
                if (OsType.current.isUnixoid()) {
                    val perms = mutableSetOf(PosixFilePermission.OWNER_READ,
                                             PosixFilePermission.OWNER_WRITE,
                                             PosixFilePermission.OWNER_EXECUTE)
                    Files.setPosixFilePermissions(hiddenServiceDirectory.toPath(), perms)
                }
            } catch (e: Exception) {
                logger?.error("could not set permissions, hidden service $hsDirName will most probably not work", e)
            }

            control.enableHiddenServiceEvents()
            // Watch for the hostname file being created/updated
            val hostNameFileObserver = context.generateWriteObserver(hostnameFile)
            // Use the control connection to update the Tor config
            config.addAll(listOf("${HS_DIR} ${hostnameFile.parentFile.canonicalPath}",
                                 "${HS_PORT} $hiddenServicePort ${LOCAL_IP}:$localPort"))
            control.saveConfig(config)
            // Wait for the hostname file to be created/updated
            if (!hostNameFileObserver.poll(HOSTNAME_TIMEOUT.toLong(), MILLISECONDS)) {
                hostnameFile.parentFile.log()
                throw RuntimeException("Wait for hidden service hostname file to be created expired.")
            }

            // Publish the hidden service's onion hostname in transport properties
            val hostname = hostnameFile.readBytes().toString(Charsets.UTF_8).trim()
            logger?.debug("PUBLISH: Hidden service config has completed: $config")

            return HsContainer(hostname, eventHandler)
        }
    }

    @Throws(TorCtlException::class, IOException::class)
    fun unpublishHiddenService(hsDir: String) {
        synchronized(control) {

            val currentHiddenServices = control.hiddenServices
            val hiddenServiceDirectory = context.getHiddenServiceDirectory(hsDir)
            val conf = mutableListOf<String>()
            var removeNext = false
            for (service in currentHiddenServices) {
                if (removeNext) {
                    removeNext = false
                    continue
                }
                if (service.is_default) {
                    continue
                }


                if (service.key == (HS_DIR) && service.value == hiddenServiceDirectory.canonicalPath) {
                    removeNext = true
                    continue
                }

                conf.add("${service.key} ${service.value}")
            }
            logger?.debug("UNPUBL Hidden service config has completed: $conf")
            control.saveConfig(conf)
        }
    }

    fun isHiddenServiceAvailable(onionUrl: String): Boolean = control.hsAvailable(onionUrl)


    /**
     * Returns the root directory in which the Tor Onion Proxy keeps its files.
     * This is mostly intended for debugging purposes.
     *
     * @return Working directory for Tor Onion Proxy files
     */
    val workingDirectory: File get() = context.workingDirectory

    fun shutdown() {
        synchronized(control) {
            control.shutdown()
        }
    }
}
