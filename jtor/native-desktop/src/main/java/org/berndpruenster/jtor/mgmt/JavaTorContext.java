/*
Copyright (c) 2016, 2017 Bernd Prünster
Copyright (c) 2014-2015 Microsoft Open Technologies, Inc.
All Rights Reserved
Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

THIS CODE IS PROVIDED ON AN *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED,
INCLUDING WITHOUT LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A PARTICULAR PURPOSE,
MERCHANTABLITY OR NON-INFRINGEMENT.

See the Apache 2 License for the specific language governing permissions and limitations under the License.
*/

package org.berndpruenster.jtor.mgmt;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;

class JavaTorContext extends TorContext {

  private static final String FILE_ARCHIVE     = "tor.tar.xz";
  private static final String BINARY_TOR_MACOS = "tor.real";
  private static final String BINARY_TOR_WIN   = "tor.exe";
  private static final String BINARY_TOR_LNX   = "tor";
  private static final String PATH_LNX         = "linux/";
  private static final String PATH_LNX64       = PATH_LNX + "x64/";
  private static final String PATH_LNX32       = PATH_LNX + "x86/";
  private static final String PATH_MACOS       = "osx/";
  private static final String PATH_MACOS64     = PATH_MACOS + "x64/";
  private static final String PATH_WIN         = "windows/";
  private static final String PATH_WIN32       = PATH_WIN + "x86/";
  private static final String PATH_NATIVE      = "native/";

  JavaTorContext(final File workingDirectory) {
    super(workingDirectory);
  }

  @Override
  public WriteObserver generateWriteObserver(final File file) {
    try {
      return new JavaWatchObserver(file);
    } catch (final IOException e) {
      throw new RuntimeException("Could not create JavaWatchObserver", e);
    }
  }

  @Override
  protected InputStream getAssetOrResourceByName(final String fileName) throws IOException {
    return getClass().getResourceAsStream("/" + fileName);
  }

  @Override
  String getProcessId() {
    // This is a horrible hack. It seems like more JVMs will return the
    // process's PID this way, but not guarantees.
    final String processName = java.lang.management.ManagementFactory.getRuntimeMXBean().getName();
    return processName.split("@")[0];
  }

  @Override
   void installFiles() throws IOException, InterruptedException {
    super.installFiles();
    switch (OsData.getOsType()) {
    case WIN:
    case LNX32:
    case LNX64:
    case MACOS:
      FileUtilities.extractContentFromArchive(getWorkingDirectory(),
          getAssetOrResourceByName(getPathToTorExecutable() + FILE_ARCHIVE));
      break;
    default:
      throw new RuntimeException("We don't support Tor on this OS yet");
    }
  }

  @Override
  protected String getPathToTorExecutable() {

    switch (OsData.getOsType()) {
    case WIN:
      return PATH_NATIVE + PATH_WIN32; // We currently only support the
    // x86 build but that should work
    // everywhere
    case MACOS:
      return PATH_NATIVE + PATH_MACOS64; // I don't think there even is a x32
    // build of Tor for MACOS, but could be
    // wrong.
    case LNX32:
      return PATH_NATIVE + PATH_LNX32;
    case LNX64:
      return PATH_NATIVE + PATH_LNX64;
    default:
      throw new RuntimeException("We don't support Tor on this OS");
    }
  }

  @Override
  protected String getPathToRC() {
    return getRCPath() + FILE_TORRC_NATIVE;
  }

  private String getRCPath() {
    switch (OsData.getOsType()) {
    case WIN:
      return PATH_NATIVE + PATH_WIN; // We currently only support the
    // x86 build but that should work
    // everywhere
    case MACOS:
      return PATH_NATIVE + PATH_MACOS; // I don't think there even is a x32
    // build of Tor for MACOS, but could be
    // wrong.
    case LNX32:
    case LNX64:
      return PATH_NATIVE + PATH_LNX;
    default:
      throw new RuntimeException("We don't support Tor on this OS");
    }
  }

  @Override
  protected String getTorExecutableFileName() {
    switch (OsData.getOsType()) {
    case LNX32:
    case LNX64:
      return BINARY_TOR_LNX;
    case WIN:
      return BINARY_TOR_WIN;
    case MACOS:
      return BINARY_TOR_MACOS;
    default:
      throw new RuntimeException("We don't support Tor on this OS");
    }
  }
}
