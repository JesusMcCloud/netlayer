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
import java.nio.file.*
import java.util.concurrent.TimeUnit

/**
 * Watches to see if a particular file is changed
 */
class NativeWatchObserver(private val fileToWatch: File) : WriteObserver {
    private val watchService: WatchService
    private val key: WatchKey
    private val lastModified: Long
    private val length: Long

    init {
        if (!fileToWatch.exists()) {
            throw  RuntimeException("$fileToWatch does not exist")
        }

        lastModified = fileToWatch.lastModified()
        length = fileToWatch.length()

        watchService = FileSystems.getDefault().newWatchService()
        // Note that poll depends on us only registering events that are of current
        // path
        if (OsType.current != OsType.MACOS) {
            key = fileToWatch.parentFile.toPath().register(watchService,
                                                           StandardWatchEventKinds.ENTRY_CREATE,
                                                           StandardWatchEventKinds.ENTRY_DELETE,
                                                           StandardWatchEventKinds.ENTRY_MODIFY)
        } else {
            // Unfortunately the default watch service on MACOS is broken, it uses a
            // separate thread and really slow polling to detect file changes
            // rather than integrating with the OS. There is a hack to make it poll
            // faster which we can use for now. See
            // http://stackoverflow.com/questions/9588737/is-java-7-watchservice-slow-for-anyone-else
            key = fileToWatch.parentFile.toPath().register(watchService,
                                                           arrayOf(StandardWatchEventKinds.ENTRY_CREATE,
                                                                   StandardWatchEventKinds.ENTRY_DELETE,
                                                                   StandardWatchEventKinds.ENTRY_MODIFY))
        }
    }

    override fun poll(timeout: Long, unit: TimeUnit): Boolean {
        var result = false
        try {
            var remainingTimeoutInNanos = unit.toNanos(timeout)
            while (remainingTimeoutInNanos > 0) {
                val startTimeInNanos = System.nanoTime()
                val receivedKey = watchService.poll(remainingTimeoutInNanos, TimeUnit.NANOSECONDS)
                val timeWaitedInNanos = System.nanoTime() - startTimeInNanos

                if (receivedKey != null) {
                    if (receivedKey != key) {
                        throw  RuntimeException("This really shouldn't have happened. EEK!" + receivedKey.toString())
                    }

                    for (event in receivedKey.pollEvents()) {
                        val kind = event.kind()

                        if (kind == StandardWatchEventKinds.OVERFLOW) {
                            logger.error("We got an overflow, there shouldn't have been enough activity to make that happen.")
                        }

                        val changedEntry = event.context() as Path
                        if (fileToWatch.toPath().endsWith(changedEntry)) {
                            result = true
                            return result
                        }
                    }

                    // In case we haven't yet gotten the event we are looking for we have
                    // to reset in order to
                    // receive any further notifications.
                    if (!key.reset()) {
                        logger.error("The key became invalid which should not have happened.")
                    }
                }

                if (timeWaitedInNanos >= remainingTimeoutInNanos) {
                    break
                }

                remainingTimeoutInNanos -= timeWaitedInNanos
            }

            // Even with the high sensitivity setting above for the MACOS the polling
            // still misses changes so I've added
            // a last modified check as a backup. Except I personally witnessed last
            // modified not returning a new value
            // value even when I saw the file change!!!! So I'm also adding in a
            // length check. Java really seems to
            // have an issue with the OS/X file system.
            result = (fileToWatch.lastModified() != lastModified) || (fileToWatch.length() != length)
            return result
        } finally {
            if (result) {
                watchService.close()
            }
        }
    }
}
