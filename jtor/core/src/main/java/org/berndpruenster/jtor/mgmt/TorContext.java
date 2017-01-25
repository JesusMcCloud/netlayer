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
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * This class encapsulates data that is handled differently in Java and ANDROID
 * as well as managing file locations.
 */
abstract public class TorContext {
  private static final String   FILE_AUTH_COOKIE  = ".tor/control_auth_cookie";
  private static final String   DIR_HS_ROOT       = "hiddenservice";
  private static final String   FILE_GEOIP        = "geoip";
  private static final String   FILE_GEOIP_6      = "geoip6";
  private static final String   FILE_TORRC        = "torrc";

  protected static final String FILE_TORRC_NATIVE = "torrc.native";
  private static final String   FILE_HOSTNAME     = "hostname";
  protected final File          workingDirectory;
  protected final File          geoIpFile;
  protected final File          geoIpv6File;
  protected final File          torrcFile;
  protected final File          torExecutableFile;
  protected final File          cookieFile;

  protected TorContext(final File workingDirectory) {
    this.workingDirectory = workingDirectory;
    geoIpFile = new File(getWorkingDirectory(), FILE_GEOIP);
    geoIpv6File = new File(getWorkingDirectory(), FILE_GEOIP_6);
    torrcFile = new File(getWorkingDirectory(), FILE_TORRC);
    torExecutableFile = new File(getWorkingDirectory(), getTorExecutableFileName());
    cookieFile = new File(getWorkingDirectory(), FILE_AUTH_COOKIE);
  }

  void installFiles() throws IOException, InterruptedException {
    // This is sleezy but we have cases where an old instance of the Tor OP
    // needs an extra second to
    // clean itself up. Without that time we can't do things like delete its
    // binary (which we currently
    // do by default, something we hope to fix with
    // https://github.com/thaliproject/Tor_Onion_Proxy_Library/issues/13
    Thread.sleep(1000, 0);
    if (getWorkingDirectory().listFiles() != null) {
      for (final File f : getWorkingDirectory().listFiles()) {
        if (f.getAbsolutePath().startsWith(torrcFile.getAbsolutePath())) {
          f.delete();
        }
      }
    }
    try {
      final File dotTorDir = new File(getWorkingDirectory(), ".tor");
      if (dotTorDir.exists()) {
        FileUtilities.recursiveFileDelete(dotTorDir);
      }
    } catch (final Exception e) {
    }
    if (!(workingDirectory.exists() || workingDirectory.mkdirs())) {
      throw new RuntimeException("Could not create root directory!");
    }

    try (final InputStream in = getAssetOrResourceByName(FILE_GEOIP)) {
      FileUtilities.cleanInstallOneFile(in, geoIpFile);
    }
    try (final InputStream in = getAssetOrResourceByName(FILE_GEOIP_6)) {
      FileUtilities.cleanInstallOneFile(in, geoIpv6File);
    }
    try (final InputStream in = getAssetOrResourceByName(FILE_TORRC)) {
      FileUtilities.cleanInstallOneFile(in, torrcFile);
    }
  }

  /**
   * Sets environment variables and working directory needed for Tor
   *
   * @param processBuilder
   *          we will call start on this to run Tor
   */
  void setEnvironmentArgsAndWorkingDirectoryForStart(final ProcessBuilder processBuilder) {
    processBuilder.directory(getWorkingDirectory());
    final Map<String, String> environment = processBuilder.environment();
    environment.put("HOME", getWorkingDirectory().getAbsolutePath());
    switch (OsData.getOsType()) {
    case LNX32:
    case LNX64:
      // We have to provide the LD_LIBRARY_PATH because when looking
      // for dynamic libraries
      // Linux apparently will not look in the current directory by
      // default. By setting this
      // environment variable we fix that.
      environment.put("LD_LIBRARY_PATH", getWorkingDirectory().getAbsolutePath());
      //$FALL-THROUGH$
    default:
      break;
    }
  }

  public String[] getEnvironmentArgsForExec() {
    final List<String> envArgs = new ArrayList<>();
    envArgs.add("HOME=" + getWorkingDirectory().getAbsolutePath());
    switch (OsData.getOsType()) {
    case LNX32:
    case LNX64:
      // We have to provide the LD_LIBRARY_PATH
      envArgs.add("LD_LIBRARY_PATH=" + getWorkingDirectory().getAbsolutePath());
      //$FALL-THROUGH$
    default:
      break;
    }
    return envArgs.toArray(new String[envArgs.size()]);
  }

  File getGeoIpFile() {
    return geoIpFile;
  }

  File getGeoIpv6File() {
    return geoIpv6File;
  }

  File getTorrcFile() {
    return torrcFile;
  }

  File getCookieFile() {
    return cookieFile;
  }

  File getHostNameFile(final String hsDir) throws IOException {
    return new File(getHiddenServiceDirectory(hsDir).getCanonicalPath() + "/" + FILE_HOSTNAME);
  }

  File getTorExecutableFile() {
    return torExecutableFile;
  }

  File getWorkingDirectory() {
    return workingDirectory;
  }

  void deleteAllFilesButHiddenServices() throws InterruptedException {
    // It can take a little bit for the Tor OP to detect the connection is
    // dead and kill itself
    Thread.sleep(1000);
    for (final File file : getWorkingDirectory().listFiles()) {
      if (file.isDirectory()) {
        if (!file.getName().equals(DIR_HS_ROOT)) {
          FileUtilities.recursiveFileDelete(file);
        }
      } else {
        if (!file.delete()) {
          throw new RuntimeException("Could not delete file " + file.getAbsolutePath());
        }
      }
    }
  }

  /**
   * Files we pull out of the AAR or JAR are typically at the root but for
   * executables outside of ANDROID the executable for a particular platform is
   * in a specific sub-directory.
   *
   * @return Path to executable in JAR Resources
   */
  protected abstract String getPathToTorExecutable();

  protected abstract String getPathToRC();

  protected abstract String getTorExecutableFileName();

  abstract String getProcessId();

  abstract WriteObserver generateWriteObserver(File file);

  protected abstract InputStream getAssetOrResourceByName(String fileName) throws IOException;

  File getHiddenServiceDirectory(final String hsDir) {
    return new File(getWorkingDirectory(), "/" + DIR_HS_ROOT + "/" + hsDir);
  }
}
