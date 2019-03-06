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
import java.security.MessageDigest
import java.util.concurrent.TimeUnit

/**
 * Watches to see if a particular file is changed
 */
class NativeWatchObserver(private val fileToWatch: File) : WriteObserver {
    private var lastDigest: ByteArray

    private var messageDigestCreator: MessageDigest

    init {
        if (!fileToWatch.exists()) {
            throw  RuntimeException("$fileToWatch does not exist")
        }

        messageDigestCreator = MessageDigest.getInstance("SHA-256")
        lastDigest = messageDigestCreator.digest(fileToWatch.readBytes())
    }

    override fun poll(timeout: Long, unit: TimeUnit): Boolean {
        var result = false
        var remaining = unit.toMillis(timeout)
        while (remaining > 0 && !result) {
            Thread.sleep(250)
            result = !lastDigest.contentEquals(messageDigestCreator.digest(fileToWatch.readBytes()))

            remaining -= 250
        }

        return result
    }
}
