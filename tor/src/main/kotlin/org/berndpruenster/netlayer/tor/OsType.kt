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

import java.io.IOException
import java.util.*

enum class OsType { WIN,
    LNX32,
    LNX64,
    LNXARMHF,
    LNXARM64,
    MACOS,
    ANDROID;

    companion object {
        @JvmStatic
        val current: OsType by lazy {
            //This also works for ART
            if (System.getProperty("java.vm.name").contains("Dalvik")) {
                ANDROID
            } else {
                val osName = System.getProperty("os.name")
                when {
                    osName.contains("Windows") -> WIN
                    osName.contains("Mac")     -> MACOS
                    osName.contains("Linux")   -> getLinuxType()
                    else                       -> throw RuntimeException("Unsupported OS: $osName")
                }
            }
        }

        private fun getLinuxType(): OsType {
            val cmd = arrayOf("uname", "-m")
            val unameProcess = Runtime.getRuntime().exec(cmd)
            try {
                val unameOutput: String

                val scanner = Scanner(unameProcess.inputStream)
                if (scanner.hasNextLine()) {
                    unameOutput = scanner.nextLine()
                    scanner.close()
                } else {
                    scanner.close()
                    throw  RuntimeException("Couldn't get output from uname call")
                }

                val exit = unameProcess.waitFor()
                if (exit != 0) {
                    throw  RuntimeException("Uname returned error code $exit")
                }

                if (unameOutput.matches(Regex("i.86"))) {
                    return LNX32
                }
                if (unameOutput.compareTo("x86_64") == 0) {
                    return LNX64
                }
                if (unameOutput.matches(Regex("arm.+"))) {
                    return LNXARMHF
                }
                if (unameOutput.compareTo("aarch64") == 0) {
                    return LNXARM64
                }
                throw  RuntimeException("Could not understand uname output, not sure what bitness")
            } catch (e: IOException) {
                throw  RuntimeException("Uname failure", e)
            } catch (e: InterruptedException) {
                throw  RuntimeException("Uname failure", e)
            } finally {
                unameProcess.destroy()
            }
        }

    }

    fun isUnixoid(): Boolean {
        return listOf(LNX32, LNX64, LNXARMHF, LNXARM64, MACOS).contains(this)
    }
}
