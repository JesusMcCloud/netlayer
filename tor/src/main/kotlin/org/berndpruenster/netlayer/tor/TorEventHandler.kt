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

import net.freehaven.tor.control.EventHandler
import kotlin.concurrent.thread

private const val UPLOADED = "UPLOADED"
private const val RECEIVED = "RECEIVED"

/**
 * Manages and triggers the ready-callbacks
 */
class TorEventHandler : EventHandler {

    private val listenerMap = HashMap<String, () -> Unit>()

    class HiddenServiceSocketList(private val hs: HiddenServiceSocket, private val listeners: List<(socket: HiddenServiceSocket) -> Unit>) : () -> Unit {
        override fun invoke() {
            listeners.forEach {
                thread{it(hs)}
            }
        }
    }

    fun attachReadyListeners(hs: HiddenServiceSocket, listeners: List<(socket: HiddenServiceSocket) -> Unit>) {
        synchronized(listenerMap) {
            listenerMap.put(hs.socketAddress.serviceName, HiddenServiceSocketList(hs, listeners))
        }
    }

    fun attachHSReadyListener(serviceName: String, listener: () -> Unit) {
        synchronized(listenerMap) {
            listenerMap.put(serviceName, listener)
        }
    }

    override fun circuitStatus(status: String, id: String, path: String) {
        val msg = "CircuitStatus: $id $status $path"
        logger?.debug(msg)
    }

    override fun streamStatus(status: String, id: String, target: String) {
        val msg = "streamStatus: status: $status $id: , target: $target"
        logger?.debug(msg)

    }

    override fun orConnStatus(status: String, orName: String) {
        val msg = "OR connection: status: $status, orName: $orName"
        logger?.debug(msg)
    }

    override fun bandwidthUsed(read: Long, written: Long) {
        logger?.debug("bandwidthUsed: read: $read , written: $written")
    }

    override fun newDescriptors(orList: List<String>) {

        val stringBuilder = StringBuilder("newDescriptors: ")

        orList.forEach {
            stringBuilder.append(it)
        }
        logger?.debug(stringBuilder.toString())

    }

    override fun message(severity: String, msg: String) {
        val msg2 = "message: severity: $severity , msg: $msg"
        logger?.trace(msg2)
    }

    override fun hiddenServiceEvent(type: String, msg: String) {
        logger?.debug("hiddenService: HS_DESC $msg")
        when(type) {
            UPLOADED -> {
                val hiddenServiceID = "${msg.split(" ")[1]}.onion"
                synchronized(listenerMap) {
                    logger?.info("Hidden Service $hiddenServiceID has been announced to the Tor network.")
                    listenerMap[hiddenServiceID]?.run {thread(block = this)}
                    listenerMap.remove(hiddenServiceID)
                }
            }
        }
    }

    override fun hiddenServiceFailedEvent(reason: String, msg: String) {
        logger?.debug("hiddenService: HS_DESC $msg")
    }

    override fun hiddenServiceDescriptor(descriptorId: String, descriptor: String, msg: String) {
        logger?.debug("hiddenService: HS_DESC_CONTENT $descriptorId $descriptor, as in $msg")
    }

    override fun timeout() {
        logger?.debug("The control connection to tor did not provide a response within one minute of waiting.")
    }

    override fun unrecognized(type: String, msg: String) {
        val msg2 = "unrecognized: current: $type , $msg: msg"
        logger?.debug(msg2)
    }

}
