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
private const val PATH_MACOS = "osx/"
private const val PATH_MACOS64 = "${PATH_MACOS}x64/"
private const val PATH_WIN = "windows/"
private const val PATH_WIN32 = "${PATH_WIN}x86/"
private const val PATH_NATIVE = "native/"

private const val OS_UNSUPPORTED = "We don't support Tor on this OS"

class NativeTor(workingDirectory: File, bridgeLines: Collection<String>? = null) : Tor(NativeContext(workingDirectory),
                                                                                       bridgeLines)


class NativeContext(workingDirectory: File) : TorContext(workingDirectory) {

    override val processId: String
        get() {
            val processName = java.lang.management.ManagementFactory.getRuntimeMXBean().name
            return processName.split("@")[0]
        }

    override val pathToTorExecutable: String by lazy {
        when (OsType.current) {
            OsType.WIN   -> PATH_NATIVE + PATH_WIN32
            OsType.MACOS -> PATH_NATIVE + PATH_MACOS64
            OsType.LNX32 -> PATH_NATIVE + PATH_LNX32
            OsType.LNX64 -> PATH_NATIVE + PATH_LNX64
            else         -> throw  RuntimeException(OS_UNSUPPORTED)
        }
    }

    private val rcPath: String by lazy {
        when (OsType.current) {
            OsType.WIN                 -> PATH_NATIVE + PATH_WIN
            OsType.MACOS               -> PATH_NATIVE + PATH_MACOS
            OsType.LNX32, OsType.LNX64 -> PATH_NATIVE + PATH_LNX
            else                       -> throw  RuntimeException(OS_UNSUPPORTED)
        }
    }
    override val pathToRC: String = "$rcPath$FILE_TORRC_NATIVE"

    override val torExecutableFileName: String by lazy {
        when (OsType.current) {
            OsType.LNX32, OsType.LNX64 -> BINARY_TOR_LNX
            OsType.WIN                 -> BINARY_TOR_WIN
            OsType.MACOS               -> BINARY_TOR_MACOS
            else                       -> throw  RuntimeException(OS_UNSUPPORTED)
        }
    }

    override fun getAssetOrResourceByName(fileName: String) = this::class.java.getResourceAsStream("/$fileName") ?: throw IOException(
            "Could not load $fileName")

    override fun generateWriteObserver(file: File): WriteObserver = NativeWatchObserver(file)

    override fun installFiles() {
        super.installFiles()
        when (OsType.current) {
            OsType.WIN, OsType.LNX32, OsType.LNX64, OsType.MACOS -> extractContentFromArchive(workingDirectory,
                                                                                              getAssetOrResourceByName(
                                                                                                      pathToTorExecutable + FILE_ARCHIVE))
            else                                                 -> throw RuntimeException(OS_UNSUPPORTED)
        }
    }
}
