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

import java.io.File
import java.io.IOException

private const val FILE_ARCHIVE = "tor.tar.xz"
private const val BINARY_TOR_MACOS = "tor.real"
private const val BINARY_TOR_WIN = "tor.exe"
private const val BINARY_TOR_LNX = "tor"
private const val PATH_LNX = "linux/"
private const val PATH_LNX64 = "${PATH_LNX}x64/"
private const val PATH_LNX32 = "${PATH_LNX}x86/"
private const val PATH_LNXARMHF = "${PATH_LNX}armhf/"
private const val PATH_LNXARM64 = "${PATH_LNX}arm64/"
private const val PATH_MACOS = "osx/"
private const val PATH_MACOS64 = "${PATH_MACOS}x64/"
private const val PATH_WIN = "windows/"
private const val PATH_WIN32 = "${PATH_WIN}x86/"
private const val PATH_NATIVE = "native/"

private const val OS_UNSUPPORTED = "We don't support Tor on this OS"

class NativeTor @JvmOverloads @Throws(TorCtlException::class) constructor(workingDirectory: File, bridgeLines: Collection<String>? = null, torrcOverrides: Torrc? = null, automaticShutdown : Boolean = true) : Tor() {

	private val context : NativeContext = NativeContext(workingDirectory, torrcOverrides)

    private val bridgeConfig: List<String> = bridgeLines?.filter { it.length > 10 } ?: emptyList()

    private lateinit var myTorController : TorController
    init {
        try {
            var done = false
            loop@ for (retryCount in 1..TRIES_PER_STARTUP) {
                myTorController = context.installAndStartTorOp(bridgeConfig, eventHandler)
                myTorController.enableNetwork()
                // We will check every second to see if boot strapping has
                // finally finished
                for (secondsWaited in 1..TOTAL_SEC_PER_STARTUP) {
                    if (!myTorController.bootstrapped) {
                        Thread.sleep(1000, 0)
                    } else {
                        torController = myTorController
                        control = Control(torController)
                        if(automaticShutdown)
                            Runtime.getRuntime().addShutdownHook(Thread({ control.shutdown() }))
                        done = true
                        break@loop
                    }
                }
                if(::myTorController.isInitialized && !done) {

                    // Bootstrapping isn't over so we need to restart and try again
                    myTorController.shutdown()

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
            }

            if(!done)
                throw TorCtlException("Could not setup Tor")


        } catch (e: IOException) {
            throw TorCtlException("Could not setup Tor", e)
        } finally {
            // Make sure we return the Tor OP in some kind of consistent state,
            // even if it's 'off'.
            if (::myTorController.isInitialized && !myTorController.bootstrapped) {
                try {
                    context.deleteAllFilesButHS()
                    myTorController.shutdown()
                } catch (e: Exception) {
                    logger?.error { e.localizedMessage }
                }
            }
        }
    }

    override fun preprocessHsDirName(hsDirName: String): File {
        return context.getHiddenServiceDirectory(hsDirName)
    }

    override fun shutdown() {
        synchronized(control) {
            try {
                // unpublish hidden services
                while(activeHiddenServices.isNotEmpty())
                    unpublishHiddenService(activeHiddenServices[0])
            } finally {
                control.shutdown()
            }
        }

    }
}


class NativeContext(workingDirectory: File, overrides: Torrc?) : TorContext(workingDirectory, overrides) {

    override val processId: String
        get() {
            val processName = java.lang.management.ManagementFactory.getRuntimeMXBean().name
            return processName.split("@")[0]
        }

    override val pathToTorExecutable: String by lazy {
        when (OsType.current) {
            OsType.WIN -> PATH_NATIVE + PATH_WIN32
            OsType.MACOS -> PATH_NATIVE + PATH_MACOS64
            OsType.LNX32 -> PATH_NATIVE + PATH_LNX32
            OsType.LNX64 -> PATH_NATIVE + PATH_LNX64
            OsType.LNXARMHF -> PATH_NATIVE + PATH_LNXARMHF
            OsType.LNXARM64 -> PATH_NATIVE + PATH_LNXARM64
            else -> throw  RuntimeException(OS_UNSUPPORTED)
        }
    }

    private val rcPath: String by lazy {
        when (OsType.current) {
            OsType.WIN -> PATH_NATIVE + PATH_WIN
            OsType.MACOS -> PATH_NATIVE + PATH_MACOS
            OsType.LNX32, OsType.LNX64, OsType.LNXARMHF, OsType.LNXARM64 -> PATH_NATIVE + PATH_LNX
            else -> throw  RuntimeException(OS_UNSUPPORTED)
        }
    }
    override val pathToRC: String = "$rcPath$FILE_TORRC_NATIVE"

    override val torExecutableFileName: String by lazy {
        when (OsType.current) {
            OsType.LNX32, OsType.LNX64, OsType.LNXARMHF, OsType.LNXARM64 -> BINARY_TOR_LNX
            OsType.WIN -> BINARY_TOR_WIN
            OsType.MACOS -> BINARY_TOR_MACOS
            else -> throw  RuntimeException(OS_UNSUPPORTED)
        }
    }

    override fun getByName(fileName: String) = this::class.java.getResourceAsStream("/$fileName") ?: throw IOException(
            "Could not load $fileName")

    override fun generateWriteObserver(file: File): WriteObserver = NativeWatchObserver(file)

    override fun installFiles() {
        super.installFiles()
        when (OsType.current) {
            OsType.WIN, OsType.LNX32, OsType.LNX64, OsType.LNXARMHF, OsType.LNXARM64, OsType.MACOS -> extractContentFromArchive(workingDirectory,
                    getByName(
                            pathToTorExecutable + FILE_ARCHIVE))
            else -> throw RuntimeException(OS_UNSUPPORTED)
        }
    }
}
