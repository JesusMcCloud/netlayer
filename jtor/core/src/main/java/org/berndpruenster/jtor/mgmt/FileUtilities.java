/*
Copyright (c) 2016, 2017 Bernd Prünster
Copyright (c) 2014-2015 Microsoft Open Technologies, Inc.
All Rights Reserved
Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance
with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

THIS CODE IS PROVIDED ON AN *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, EITHER EXPRESS OR
IMPLIED, INCLUDING WITHOUT LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A PARTICULAR
PURPOSE, MERCHANTABLITY OR NON-INFRINGEMENT.

See the Apache 2 License for the specific language governing permissions and limitations under the License.
*/

package org.berndpruenster.jtor.mgmt;

import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.apache.commons.compress.archivers.ArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.compressors.xz.XZCompressorInputStream;
import org.apache.commons.compress.utils.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FileUtilities {
  private static final Logger LOG = LoggerFactory.getLogger(FileUtilities.class);

  private FileUtilities() {
  }

  static void logFiles(final File f) {
    if (f.isDirectory()) {
      for (final File child : f.listFiles()) {
        logFiles(child);
      }
    } else {
      LOG.info(f.getAbsolutePath());
    }
  }

  static byte[] read(final File f) throws IOException {
    final byte[] b = new byte[(int) f.length()];
    try (final FileInputStream in = new FileInputStream(f)) {
      int offset = 0;
      while (offset < b.length) {
        final int read = in.read(b, offset, b.length - offset);
        if (read == -1) {
          throw new EOFException();
        }
        offset += read;
      }
      return b;
    }
  }

  /**
   * Reads the input stream, deletes fileToWriteTo if it exists and over writes
   * it with the stream.
   *
   * @param readFrom
   *          Stream to read from
   * @param fileToWriteTo
   *          File to write to
   * @throws java.io.IOException
   *           - If any of the file operations fail
   */
  static void cleanInstallOneFile(final InputStream readFrom, final File fileToWriteTo) throws IOException {
    if (fileToWriteTo.exists() && !fileToWriteTo.delete()) {
      throw new RuntimeException("Could not remove existing file " + fileToWriteTo.getName());
    }
    try (final OutputStream out = new FileOutputStream(fileToWriteTo)) {
      IOUtils.copy(readFrom, out);
    }
  }

  static void recursiveFileDelete(final File fileOrDirectory) {
    if (fileOrDirectory.isDirectory()) {
      for (final File child : fileOrDirectory.listFiles()) {
        recursiveFileDelete(child);
      }
    }

    if (fileOrDirectory.exists() && !fileOrDirectory.delete()) {
      throw new RuntimeException("Could not delete directory " + fileOrDirectory.getAbsolutePath());
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
  static void extractContentFromArchive(final File destinationDirectory, final InputStream archiveInputStream)
      throws IOException {
    try (final TarArchiveInputStream in = new TarArchiveInputStream(new XZCompressorInputStream(archiveInputStream))) {
      ArchiveEntry entry;
      while ((entry = in.getNextEntry()) != null) {

        final File f = new File(destinationDirectory.getCanonicalPath() + File.separator
            + entry.getName().replace('/', File.separatorChar));
        if (entry.isDirectory()) {
          if (!f.exists() && !f.mkdirs()) {
            throw new IOException("could not create directory " + f);
          }
        } else {
          if (f.exists() && !f.delete()) {
            throw new RuntimeException(
                "Could not delete file in preparation for overwriting it. File - " + f.getAbsolutePath());
          }

          if (!f.createNewFile()) {
            throw new RuntimeException("Could not create file " + f);
          }

          try (final OutputStream fileOutputStream = new FileOutputStream(f)) {
            IOUtils.copy(in, fileOutputStream);
            final int mode = ((TarArchiveEntry) entry).getMode();
            //octal representation
            if ((mode & 00100) > 0) {
              f.setExecutable(true, (mode & 00001) == 0);
            }
          }
        }
      }
    }
  }
}
