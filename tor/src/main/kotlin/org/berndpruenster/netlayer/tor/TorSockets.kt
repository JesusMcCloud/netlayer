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
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.*
import java.nio.channels.SocketChannel
import java.util.*

private const val RETRY_SLEEP: Long = 500

data class HiddenServiceSocketAddress(val serviceName: String, val hiddenServicePort: Int) : SocketAddress() {
    override fun toString(): String = "HiddenServiceSocket[addr=$serviceName,port=$hiddenServicePort]"
}

class TorSocket @JvmOverloads @Throws(IOException::class) constructor(private val destination: String,
                                                                      port: Int,
                                                                      streamId: String? = null,
                                                                      numTries: Int = 5,
                                                                      tor: Tor? = null) : Socket() {
    @JvmOverloads @Throws(IOException::class) constructor(socketAddress: HiddenServiceSocketAddress,
                                                          streamId: String? = null,
                                                          numTries: Int = 5,
                                                          tor: Tor? = null) : this(socketAddress.serviceName,
                                                                                   socketAddress.hiddenServicePort,
                                                                                   streamId,
                                                                                   numTries,
                                                                                   tor)

    private val socket = setup(destination, port, numTries, streamId, tor)

    @Throws(IOException::class)
    override fun connect(addr: SocketAddress) = throw IOException("DONT!")

    @Throws(IOException::class)
    override fun connect(addr: SocketAddress, port: Int) = throw IOException("DONT!")

    @Throws(IOException::class)
    override fun bind(addr: SocketAddress) {
        socket.bind(addr)
    }

    override fun getInetAddress(): InetAddress = socket.inetAddress
    override fun getLocalAddress(): InetAddress = socket.localAddress
    override fun getPort(): Int = socket.port
    override fun getLocalPort(): Int = socket.localPort
    override fun getRemoteSocketAddress(): SocketAddress = HiddenServiceSocketAddress(destination, port)
    override fun getLocalSocketAddress(): SocketAddress = socket.localSocketAddress
    override fun getChannel(): SocketChannel = socket.channel
    override fun toString(): String = "TorSocket[addr=$destination,port=$port, localPort=$localPort]"
    override fun isConnected(): Boolean = socket.isConnected
    override fun isBound(): Boolean = socket.isBound
    override fun isClosed(): Boolean = socket.isClosed
    override fun isInputShutdown(): Boolean = socket.isInputShutdown
    override fun isOutputShutdown(): Boolean = socket.isOutputShutdown
    @Throws(IOException::class)
    override fun getInputStream(): InputStream = socket.getInputStream()

    @Throws(IOException::class)
    override fun getOutputStream(): OutputStream = socket.getOutputStream()

    @Throws(SocketException::class)
    override fun getTcpNoDelay(): Boolean = socket.tcpNoDelay

    @Throws(SocketException::class)
    override fun getOOBInline(): Boolean = socket.oobInline

    @Throws(SocketException::class)
    override fun getSoTimeout(): Int = socket.soTimeout

    @Throws(SocketException::class)
    override fun getSendBufferSize(): Int = socket.sendBufferSize

    @Throws(SocketException::class)
    override fun getReceiveBufferSize(): Int = socket.receiveBufferSize

    @Throws(SocketException::class)
    override fun getTrafficClass(): Int = socket.trafficClass

    @Throws(SocketException::class)
    override fun getKeepAlive(): Boolean = socket.keepAlive

    @Throws(SocketException::class)
    override fun getReuseAddress(): Boolean = socket.reuseAddress

    @Throws(SocketException::class)
    override fun getSoLinger(): Int = socket.soLinger

    @Throws(SocketException::class)
    override fun setTcpNoDelay(arg0: Boolean) {
        socket.tcpNoDelay = arg0
    }

    @Throws(SocketException::class)
    override fun setSoLinger(arg0: Boolean, arg1: Int) {
        socket.setSoLinger(arg0, arg1)
    }

    @Throws(IOException::class)
    override fun sendUrgentData(arg0: Int) {
        socket.sendUrgentData(arg0)
    }

    @Throws(SocketException::class)
    override fun setOOBInline(arg0: Boolean) {
        socket.oobInline = arg0
    }

    @Throws(SocketException::class)
    override fun setSoTimeout(arg0: Int) {
        socket.soTimeout = arg0
    }

    @Throws(SocketException::class)
    override fun setSendBufferSize(arg0: Int) {
        socket.sendBufferSize = arg0
    }

    @Throws(SocketException::class)
    override fun setReceiveBufferSize(arg0: Int) {
        socket.receiveBufferSize = arg0
    }

    @Throws(SocketException::class)
    override fun setKeepAlive(arg0: Boolean) {
        socket.keepAlive = arg0
    }

    @Throws(SocketException::class)
    override fun setTrafficClass(arg0: Int) {
        socket.trafficClass = arg0
    }

    @Throws(SocketException::class)
    override fun setReuseAddress(arg0: Boolean) {
        socket.reuseAddress = arg0
    }

    @Throws(IOException::class)
    override fun close() {
        socket.close()
    }

    @Throws(IOException::class)
    override fun shutdownInput() {
        socket.shutdownInput()
    }

    @Throws(IOException::class)
    override fun shutdownOutput() {
        socket.shutdownOutput()
    }

    override fun setPerformancePreferences(arg0: Int, arg1: Int, arg2: Int) {
        socket.setPerformancePreferences(arg0, arg1, arg2)
    }
}


class HiddenServiceSocket @JvmOverloads constructor(internalPort: Int,
                                                    private val hiddenServiceDir: String = "ephemeral hidden service",
                                                    val hiddenServicePort: Int = internalPort,
                                                    tor: Tor? = null) : ServerSocket() {

    private val mgr = getTorInstance(tor)
    private val listeners = mutableListOf<(socket: HiddenServiceSocket) -> Unit>()

    val socketAddress: HiddenServiceSocketAddress
    val serviceName: String

    init {
        val (name, handler) = mgr.publishHiddenService(hiddenServiceDir, hiddenServicePort, internalPort)
        serviceName = name
        socketAddress = HiddenServiceSocketAddress(name, hiddenServicePort)
        bind(InetSocketAddress(LOCAL_IP, internalPort))
        handler.attachReadyListeners(this, listeners)
    }

    fun addReadyListener(listener: (socket: HiddenServiceSocket) -> Unit) {
        synchronized(listeners) {
            listeners.add(listener)
        }
    }

    override fun toString(): String = socketAddress.toString()


    override fun close() {
        super.close()
        try {
            mgr.unpublishHiddenService(serviceName)
        } catch (e: TorCtlException) {
            throw  IOException(e)
        }
    }

}

@Throws(IOException::class)
private fun setup(onionUrl: String, port: Int, numTries: Int, streamID: String?, tor: Tor?): Socket {

    val before = Calendar.getInstance().timeInMillis
    val mgr = getTorInstance(tor)
    for (i in 1..numTries) {
        try {
            logger?.debug { "trying to connect to $onionUrl:$port" }
            val proxy = mgr.getProxy(streamID)
            logger?.debug { "got proxy $proxy" }
            val ssock = SocksSocket(proxy, onionUrl, port)

            logger?.debug("Took ${Calendar.getInstance().timeInMillis - before}ms to connect to " + onionUrl + ":" + port)
            ssock.tcpNoDelay = true
            return ssock
        } catch (exx: UnknownHostException) {
            logger?.debug("Try $i connecting to $onionUrl:$port failed. retrying...")
            Thread.sleep(RETRY_SLEEP)
            continue

        } catch (e: Exception) {
            throw  IOException("Cannot connect to hidden service")
        }
    }
    throw IOException("Cannot connect to HS")
}

private fun getTorInstance(tor: Tor?): Tor = tor ?: Tor.default
                                             ?: throw IOException("No default Tor Instance configured")
