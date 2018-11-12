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
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketAddress


class ExternalTor @JvmOverloads @Throws(TorCtlException::class) constructor(controlPort: Int, authentication: String) : Tor() {
    init {

        // connect to controlPort
        // authenticate

        this.control = Control(TorController(Socket()))
    }
	
    override fun publishHiddenService(hsDirName: String, hiddenServicePort: Int, localPort: Int): HsContainer {
        return HsContainer("asdf", eventHandler)
    }

    override fun unpublishHiddenService(hsDir: String) {

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