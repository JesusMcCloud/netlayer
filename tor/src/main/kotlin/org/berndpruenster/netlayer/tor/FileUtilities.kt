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
All Rights Reserved
Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance
with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

THIS CODE IS PROVIDED ON AN *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, EITHER EXPRESS OR
IMPLIED, INCLUDING WITHOUT LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A PARTICULAR
PURPOSE, MERCHANTABLITY OR NON-INFRINGEMENT.

See the Apache 2 License for the specific language governing permissions and limitations under the License.
*/

package org.berndpruenster.netlayer.tor

import org.apache.commons.compress.archivers.tar.TarArchiveEntry
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream
import org.apache.commons.compress.compressors.xz.XZCompressorInputStream
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.util.concurrent.TimeUnit

/**
 * ANDROID uses FileObserver and Java uses the WatchService, this class
 * abstracts the two.
 */
interface WriteObserver {
    /**
     * Waits timeout of unit to see if file is modified
     *
     * @param timeout
     *          How long to wait before returning
     * @param unit
     *          Unit to wait in
     * @return True if file was modified, false if it was not
     */
    fun poll(timeout: Long, unit: TimeUnit): Boolean
}

internal fun File.log() {
    if (isDirectory) {
        listFiles().forEach {
            (it.log())
        }
    } else {
        logger.info(absolutePath)
    }
}

/**
 * Reads the input stream, deletes dst if it exists and over writes
 * it with the stream.
 *
 * @param src
 *          Stream to read from
 * @param dst
 *          File to write to
 * @throws java.io.IOException
 *           - If any of the file operations fail
 */
internal fun cleanInstallFile(src: InputStream, dst: File) {
    if (dst.exists() && !dst.delete()) {
        throw  RuntimeException("Could not remove existing file ${dst.name}")
    }
    dst.outputStream().buffered().use { out ->
        src.copyTo(out)
    }
}

/**
 * @param destinationDirectory
 *          Directory files are to be extracted to
 * @param archiveInputStream
 *          Stream to extract
 * @throws java.io.IOException
 *           - If there are any file errors
 */
fun extractContentFromArchive(destinationDirectory: File, archiveInputStream: InputStream) {

    TarArchiveInputStream(XZCompressorInputStream(archiveInputStream)).use { tarIn ->
        var entry = tarIn.nextEntry

        while (entry != null) {

            val f = File(destinationDirectory.canonicalPath + File.separator + entry.name.replace('/',
                                                                                                  File.separatorChar))
            if (entry.isDirectory) {
                if (!f.exists() && !f.mkdirs()) {
                    throw  IOException("could not create directory $f")
                }
            } else {

                if (!f.parentFile.exists() && !f.parentFile.mkdirs()) {
                    throw  IOException("could not create directory  ${f.parentFile}")
                }

                if (f.exists() && !f.delete()) {
                    throw  RuntimeException("Could not delete file ${f.absolutePath} in preparation for overwriting it")
                }

                if (!f.createNewFile()) {
                    throw  RuntimeException("Could not create file $f")
                }

                FileOutputStream(f).use { outStream ->
                    tarIn.copyTo(outStream)
                    val mode = (entry as TarArchiveEntry).mode

                    if ((mode and 64) > 0) {
                        f.setExecutable(true, (mode and 1) == 0)
                    }
                    if(OsType.current==OsType.MACOS){
                        f.setExecutable(true,true)
                    }
                }
            }
            entry = tarIn.nextTarEntry
        }
    }
}

