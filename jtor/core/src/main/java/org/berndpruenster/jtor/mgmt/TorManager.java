/*
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

import static java.util.concurrent.TimeUnit.MILLISECONDS;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.attribute.PosixFilePermission;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map.Entry;
import java.util.Scanner;
import java.util.Set;
import java.util.concurrent.CountDownLatch;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.runjva.sourceforge.jsocks.protocol.Authentication;
import com.runjva.sourceforge.jsocks.protocol.Socks5Proxy;

import net.freehaven.tor.control.ConfigEntry;
import net.freehaven.tor.control.TorControlConnection;

/**
 * This is where all the fun is, this is the class that handles the heavy work.
 * Note that you will most likely need to actually call into the
 * AndroidOnionProxyManager or JavaOnionProxyManager in order to create the
 * right bindings for your environment.
 * <p/>
 * This class began life as TorPlugin from the Briar Project
 */
public abstract class TorManager {
  public static final String            LOCAL_IP                   = "127.0.0.1";

  private static final int              TOTAL_SEC_PER_STARTUP      = 4 * 60;
  private static final int              TRIES_PER_STARTUP          = 5;

  private static final String           DIRECTIVE_GEOIP6_FILE      = "GeoIPv6File ";
  private static final String           DIRECTIVE_GEOIP_FILE       = "GeoIPFile ";
  private static final String           DIRECTIVE_DATA_DIRECTORY   = "DataDirectory ";
  private static final String           DIRECTIVE_COOKIE_AUTH_FILE = "CookieAuthFile ";
  private static final String           STATUS_BOOTSTRAPPED        = "status/bootstrap-phase";
  private static final String           DISABLE_NETWORK            = "DisableNetwork";
  private static final String           HS_PORT                    = "HiddenServicePort";
  private static final String           LOCAL_ADDR_FRAGMENT        = "\"" + LOCAL_IP + ":";
  private static final String           HS_DIR                     = "HiddenServiceDir";
  private static final String           HS_OPTS                    = "HiddenServiceOptions";

  private static final String           NET_LISTENERS_SOCKS        = "net/listeners/socks";

  private static final String[]         EVENTS                     = { "CIRC", "WARN", "ERR" };
  private static final String[]         EVENTS_HS                  = { "EXTENDED", "CIRC", "ORCONN", "INFO", "NOTICE",
      "WARN", "ERR", "HS_DESC" };

  private static final String           OWNER                      = "__OwningControllerProcess";
  private static final int              COOKIE_TIMEOUT             = 3 * 1000;                                        // Milliseconds
  private static final int              HOSTNAME_TIMEOUT           = 30 * 1000;                                       // Milliseconds
  private static final Logger           LOG                        = LoggerFactory.getLogger(TorManager.class);

  protected final TorContext            context;

  private final List<String>            bridgeConfig;

  private volatile Socket               controlSocket              = null;

  // If controlConnection is not null then this means that a connection exists
  // and the Tor OP will die when
  // the connection fails.
  private volatile TorControlConnection controlConnection          = null;
  private volatile int                  controlPort;

  private final TorEventHandler         eventHandler;

  private int                           socksPort;

  protected TorManager(final TorContext torContext) throws IOException {
    this(torContext, null);
  }

  protected TorManager(final TorContext torContext, final Collection<String> bridgeLines) throws IOException {
    this.context = torContext;
    eventHandler = new TorEventHandler();
    bridgeConfig = new LinkedList<>();
    setBrigeLines(bridgeLines);
    bootstrap();
  }

  private void addBridgeLine(final String line) {
    if (line.length() > 10) {
      bridgeConfig.add(line);
    } else {
      LOG.warn("Invalid bridge line " + line + " supplied, ignoring...");
    }
  }

  private boolean startWithRepeat(final int secondsBeforeTimeOut, final int numberOfRetries)
      throws InterruptedException, IOException {
    if (secondsBeforeTimeOut <= 0 || numberOfRetries < 0) {
      throw new IllegalArgumentException("secondsBeforeTimeOut >= 0 & numberOfRetries > 0");
    }

    try {
      for (int retryCount = 0; retryCount < numberOfRetries; ++retryCount) {
        if (!installAndStartTorOp()) {
          return false;
        }
        enableNetwork();

        // We will check every second to see if boot strapping has
        // finally finished
        for (int secondsWaited = 0; secondsWaited < secondsBeforeTimeOut; ++secondsWaited) {
          if (!isBootstrapped()) {
            Thread.sleep(1000, 0);
          } else {
            return true;
          }
        }

        // Bootstrapping isn't over so we need to restart and try again
        shutdown();

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
        context.deleteAllFilesButHiddenServices();
      }

      return false;
    } finally {
      // Make sure we return the Tor OP in some kind of consistent state,
      // even if it's 'off'.
      if (!isBootstrapped()) {
        shutdown();
      }
    }
  }

  private void bootstrap() throws IOException {
    try {
      if (!startWithRepeat(TOTAL_SEC_PER_STARTUP, TRIES_PER_STARTUP)) {
        throw new IOException("Could not Start Tor. Is another instance already running?");
      }
      this.socksPort = getSocksPort();
      Runtime.getRuntime().addShutdownHook(new Thread() {
        @Override
        public void run() {
          try {
            TorManager.this.shutdown();
          } catch (final IOException e) {
            e.printStackTrace();
          }
        }
      });
    } catch (final InterruptedException e) {
      throw new IOException(e);
    }
  }

  public synchronized Socks5Proxy getProxy(final String streamID) throws TorCtlException {
    if (controlConnection == null) {
      throw new TorCtlException("This Tor instance is shut down!");
    }
    final Socks5Proxy proxy;
    try {
      proxy = new Socks5Proxy(LOCAL_IP, socksPort);
    } catch (final IOException e) {
      throw new TorCtlException(e);
    }
    proxy.resolveAddrLocally(false);
    if (streamID != null) {
      final byte[] hash;
      final String authValue;
      try {
        authValue = new BigInteger(MessageDigest.getInstance("MD5").digest(streamID.getBytes())).toString();
        hash = authValue.getBytes();
      } catch (final NoSuchAlgorithmException e) {
        throw new TorCtlException(e);
      }
      proxy.setAuthenticationMethod(2, new Authentication() {

        @Override
        public Object[] doSocksAuthentication(final int methodId, final Socket proxySocket) throws IOException {
          LOG.debug("auth'ing using " + authValue);
          proxySocket.getOutputStream().write(new byte[] { (byte) 1, (byte) hash.length });
          proxySocket.getOutputStream().write(hash);
          proxySocket.getOutputStream().write(new byte[] { (byte) 1, (byte) 0 });
          proxySocket.getOutputStream().flush();
          final byte[] status = new byte[2];
          // System.out.println("RD: " +
          proxySocket.getInputStream().read(status);
          if (status[1] != 0) {
            throw new IOException("auth error: " + status[1]);
          }
          return new Object[] { proxySocket.getInputStream(), proxySocket.getOutputStream() };
        }
      });
    }
    return proxy;
  }

  /**
   * Returns the socks port on the IPv4 localhost address that the Tor OP is
   * listening on
   *
   * @return Discovered socks port
   * @throws java.io.IOException
   *           - File errors
   */
  private int getSocksPort() throws IOException {
    // This returns a set of space delimited quoted strings which could be
    // Ipv4, Ipv6 or unix sockets
    final String[] socksIpPorts = controlConnection.getInfo(NET_LISTENERS_SOCKS).split(" ");

    for (final String address : socksIpPorts) {
      if (address.contains(LOCAL_ADDR_FRAGMENT)) {
        // Remember, the last character will be a " so we have to remove
        // that
        return Integer.parseInt(address.substring(address.lastIndexOf(":") + 1, address.length() - 1));
      }
    }

    throw new RuntimeException("We don't have an Ipv4 localhost binding for socks!");
  }

  /**
   * Publishes a hidden service
   *
   * @param hiddenServicePort
   *          The port that the hidden service will accept connections on
   * @param localPort
   *          The local port that the hidden service will relay connections to
   * @return The hidden service's onion address in the form X.onion.
   * @throws java.io.IOException
   *           - File errors
   * @throws TorCtlException
   */
  public synchronized Entry<String, TorEventHandler> publishHiddenService(final String hsDir,
      final int hiddenServicePort, final int localPort) throws TorCtlException, IOException {
    if (controlConnection == null) {
      throw new TorCtlException("Tor is not running.");
    }

    final List<ConfigEntry> currentHiddenServices = controlConnection.getConf(HS_OPTS);

    final File hiddenServiceDirectory = context.getHiddenServiceDirectory(hsDir);

    final List<String> config = new LinkedList<>();

    for (final ConfigEntry service : currentHiddenServices) {
      if (service.is_default) {
        continue;
      }
      if (service.key.equals(HS_DIR) && service.value.equals(hiddenServiceDirectory)) {
        throw new TorCtlException(
            "Hidden Service " + hiddenServiceDirectory.getCanonicalPath() + " is already published");
      }
      config.add(service.key + " " + service.value);
    }

    LOG.debug("Creating hidden service " + hsDir);
    final File hostnameFile = context.getHostNameFile(hsDir);

    if (!(hostnameFile.getParentFile().exists() || hostnameFile.getParentFile().mkdirs())) {
      throw new TorCtlException("Could not create hostnameFile parent directory");
    }

    if (!(hostnameFile.exists() || hostnameFile.createNewFile())) {
      throw new TorCtlException("Could not create hostnameFile");
    }
    // Thanks, Ubuntu!
    try {
      switch (OsData.getOsType()) {
      case LNX32:
      case LNX64:
      case MACOS: {
        final Set<PosixFilePermission> perms = new HashSet<>();
        perms.add(PosixFilePermission.OWNER_READ);
        perms.add(PosixFilePermission.OWNER_WRITE);
        perms.add(PosixFilePermission.OWNER_EXECUTE);
        Files.setPosixFilePermissions(hiddenServiceDirectory.toPath(), perms);
      }
      //$FALL-THROUGH$
      default:
        break;
      }

    } catch (final Exception e) {
      e.printStackTrace();
    }

    controlConnection.setEvents(Arrays.asList(EVENTS_HS));
    // Watch for the hostname file being created/updated
    final WriteObserver hostNameFileObserver = context.generateWriteObserver(hostnameFile);
    // Use the control connection to update the Tor config
    config.addAll(Arrays.asList(HS_DIR + " " + hostnameFile.getParentFile().getCanonicalPath(),
        HS_PORT + " " + hiddenServicePort + " " + LOCAL_IP + ":" + localPort));
    controlConnection.setConf(config);
    controlConnection.saveConf();
    // Wait for the hostname file to be created/updated
    if (!hostNameFileObserver.poll(HOSTNAME_TIMEOUT, MILLISECONDS)) {
      FileUtilities.logFiles(hostnameFile.getParentFile());
      throw new RuntimeException("Wait for hidden service hostname file to be created expired.");
    }

    // Publish the hidden service's onion hostname in transport properties
    final String hostname = new String(FileUtilities.read(hostnameFile), "UTF-8").trim();
    LOG.debug("PUBLISH: Hidden service config has completed: " + Arrays.toString(config.toArray()));

    return new HelperContainer(hostname, eventHandler);
  }

  public synchronized void unpublishHiddenService(final String hsDir) throws TorCtlException, IOException {
    if (controlConnection == null) {
      throw new TorCtlException("Tor is not running.");
    }
    final List<ConfigEntry> currentHiddenServices = controlConnection.getConf(HS_OPTS);
    final File hiddenServiceDirectory = context.getHiddenServiceDirectory(hsDir);
    final List<String> conf = new LinkedList<>();
    boolean removeNext = false;
    for (final ConfigEntry service : currentHiddenServices) {
      if (removeNext) {
        removeNext = false;
        continue;
      }
      if (service.is_default) {
        continue;
      }

      final String canonicalHSPath = hiddenServiceDirectory.getCanonicalPath();

      if (service.key.equals(HS_DIR) && service.value.equals(canonicalHSPath)) {
        removeNext = true;
        continue;
      }
      conf.add(service.key + " " + service.value);
    }
    LOG.debug("UNPUBL Hidden service config has completed: " + Arrays.toString(conf.toArray()));
    controlConnection.setConf(conf);
    controlConnection.saveConf();
  }

  public synchronized boolean isHiddenServiceAvailable(final String onionurl) throws TorCtlException {
    if (controlConnection == null) {
      throw new TorCtlException("Tor is not running.");
    }
    try {
      return controlConnection.isHSAvailable(onionurl.substring(0, onionurl.indexOf(".")));
    } catch (final IOException e) {
      e.printStackTrace();
      System.err.println("We'll have to wait for Tor 0.2.7 for HSFETCH to work!");
    }
    return false;
  }

  /**
   * Kills the Tor OP Process. Once you have called this method nothing is going
   * to work until you either call startWithRepeat or installAndStartTorOp
   *
   * @throws java.io.IOException
   *           - File errors
   */
  public synchronized void shutdown() throws IOException {
    try {
      if (controlConnection == null) {
        return;
      }
      LOG.debug("Stopping Tor");
      controlConnection.setConf(DISABLE_NETWORK, "1");
      controlConnection.shutdownTor("TERM");
    } finally {
      if (controlSocket != null) {
        controlSocket.close();
      }
      controlConnection = null;
      controlSocket = null;
    }
  }

  /**
   * Tells the Tor OP if it should accept network connections
   *
   * @param enable
   *          If true then the Tor OP will accept SOCKS connections, otherwise
   *          not.
   * @throws java.io.IOException
   *           - IO exceptions
   */
  private void enableNetwork() throws IOException {
    if (controlConnection == null) {
      throw new RuntimeException("Tor is not running!");
    }
    LOG.debug("Enabling network");
    controlConnection.setConf(DISABLE_NETWORK, "0");
  }

  private boolean isBootstrapped() {
    if (controlConnection == null) {
      return false;
    }

    String phase = null;
    try {
      phase = controlConnection.getInfo(STATUS_BOOTSTRAPPED);
    } catch (final IOException e) {
      LOG.warn("Control connection is not responding properly to getInfo", e);
    }

    if (phase != null && phase.contains("PROGRESS=100")) {
      LOG.debug("Tor has already bootstrapped");
      return true;
    }

    return false;
  }

  /**
   * Installs all necessary files and starts the Tor OP in offline mode (e.g.
   * networkEnabled(false)). This would only be used if you wanted to start the
   * Tor OP so that the install and related is all done but aren't ready to
   * actually connect it to the network.
   *
   * @return True if all files installed and Tor OP successfully started
   * @throws java.io.IOException
   *           - IO Exceptions
   * @throws java.lang.InterruptedException
   *           - If we are, well, interrupted
   */
  private boolean installAndStartTorOp() throws IOException, InterruptedException {
    // The Tor OP will die if it looses the connection to its socket so if
    // there is no controlSocket defined
    // then Tor is dead. This assumes, of course, that takeOwnership works
    // and we can't end up with Zombies.
    if (controlConnection != null) {
      LOG.info("Tor is already running");
      return true;
    }

    // The code below is why this method is synchronized, we don't want two
    // instances of it running at once
    // as the result would be a mess of screwed up files and connections.
    LOG.info("Tor is not running");

    installAndConfigureFiles();

    LOG.info("Starting Tor");
    final File cookieFile = context.getCookieFile();
    if (!cookieFile.getParentFile().exists() && !cookieFile.getParentFile().mkdirs()) {
      throw new RuntimeException("Could not create cookieFile parent directory");
    }

    // The original code from Briar watches individual files, not a
    // directory and ANDROID's file observer
    // won't work on files that don't exist. Rather than take 5 seconds to
    // rewrite Briar's code I instead
    // just make sure the file exists
    if (!cookieFile.exists() && !cookieFile.createNewFile()) {
      throw new RuntimeException("Could not create cookieFile");
    }

    final File workingDirectory = context.getWorkingDirectory();
    // Watch for the auth cookie file being created/updated
    final WriteObserver cookieObserver = context.generateWriteObserver(cookieFile);
    // Start a new Tor process
    final String torPath = context.getTorExecutableFile().getAbsolutePath();
    final String configPath = context.getTorrcFile().getAbsolutePath();
    final String pid = context.getProcessId();
    final String[] cmd = { torPath, "-f", configPath, OWNER, pid };
    final ProcessBuilder processBuilder = new ProcessBuilder(cmd);
    context.setEnvironmentArgsAndWorkingDirectoryForStart(processBuilder);
    Process torProcess = null;
    try {
      // torProcess = Runtime.getRuntime().exec(cmd, env,
      // workingDirectory);
      torProcess = processBuilder.start();
      final CountDownLatch controlPortCountDownLatch = new CountDownLatch(1);
      eatStream(torProcess.getInputStream(), false, controlPortCountDownLatch);
      eatStream(torProcess.getErrorStream(), true, null);

      // On platforms other than WIN we run as a daemon and so we need
      // to wait for the process to detach
      // or exit. In the case of WIN the equivalent is running as a
      // service and unfortunately that requires
      // managing the service, such as turning it off or uninstalling it
      // when it's time to move on. Any number
      // of errors can prevent us from doing the cleanup and so we would
      // leave the process running around. Rather
      // than do that on WIN we just let the process run on the exec
      // and hence don't look for an exit code.
      // This does create a condition where the process has exited due to
      // a problem but we should hopefully
      // detect that when we try to use the control connection.
      if (OsData.getOsType() != OsData.OsType.WIN) {
        final int exit = torProcess.waitFor();
        torProcess = null;
        if (exit != 0) {
          LOG.warn("Tor exited with value " + exit);
          return false;
        }
      }

      // Wait for the auth cookie file to be created/updated
      if (!cookieObserver.poll(COOKIE_TIMEOUT, MILLISECONDS)) {
        LOG.warn("Auth cookie not created");
        FileUtilities.logFiles(workingDirectory);
        return false;
      }

      // Now we should be able to connect to the new process
      controlPortCountDownLatch.await();
      controlSocket = new Socket(LOCAL_IP, controlPort);

      // Open a control connection and authenticate using the cookie file
      final TorControlConnection controlConnection = new TorControlConnection(controlSocket);
      controlConnection.authenticate(FileUtilities.read(cookieFile));
      // Tell Tor to exit when the control connection is closed
      controlConnection.takeOwnership();
      controlConnection.resetConf(Collections.singletonList(OWNER));

      controlConnection.setEventHandler(eventHandler);
      controlConnection.setEvents(Arrays.asList(EVENTS));

      // We only set the class property once the connection is in a known
      // good state
      this.controlConnection = controlConnection;
      return true;
    } catch (final SecurityException e) {
      LOG.warn(e.toString(), e);
      return false;
    } catch (final InterruptedException e) {
      LOG.warn("Interrupted while starting Tor", e);
      Thread.currentThread().interrupt();
      return false;
    } finally {
      if (controlConnection == null && torProcess != null) {
        // It's possible that something 'bad' could happen after we
        // executed exec but before we takeOwnership()
        // in which case the Tor OP will hang out as a zombie until this
        // process is killed. This is problematic
        // when we want to do things like
        torProcess.destroy();
      }
    }
  }

  /**
   * Returns the root directory in which the Tor Onion Proxy keeps its files.
   * This is mostly intended for debugging purposes.
   *
   * @return Working directory for Tor Onion Proxy files
   */
  public File getWorkingDirectory() {
    return context.getWorkingDirectory();
  }

  protected void eatStream(final InputStream inputStream, final boolean stdError, final CountDownLatch countDownLatch) {
    new Thread() {
      @Override
      public void run() {
        Thread.currentThread().setName(stdError ? "NFO " : "ERR ");
        final Scanner scanner = new Scanner(inputStream);
        try {
          while (scanner.hasNextLine()) {
            if (stdError) {
              LOG.error(scanner.nextLine());
            } else {
              final String nextLine = scanner.nextLine();
              // We need to find the line where it tells us what
              // the control port is.
              // The line that will appear in stdio with the
              // control port looks like:
              // Control listener listening on port 39717.
              if (nextLine.contains("Control listener listening on port ")) {
                // For the record, I hate regex so I'm doing
                // this manually
                controlPort = Integer
                    .parseInt(nextLine.substring(nextLine.lastIndexOf(" ") + 1, nextLine.length() - 1));
                countDownLatch.countDown();
              }
              LOG.debug(nextLine);
            }
          }
        } finally {
          scanner.close();
          try {
            inputStream.close();

          } catch (final IOException e) {
            LOG.error("Couldn't close input stream in eatStream", e);
          }
        }
      }
    }.start();
  }

  protected void installAndConfigureFiles() throws IOException, InterruptedException {
    context.installFiles();

    // if (!onionProxyContext.getTorExecutableFile().setExecutable(true)) {
    // throw new RuntimeException("could not make Tor executable.");
    // }

    // We need to edit the config file to specify exactly where the
    // cookie/geoip files should be stored, on
    // ANDROID this is always a fixed location relative to the configFiles
    // which is why this extra step
    // wasn't needed in Briar's ANDROID code. But in WIN it ends up in
    // the user's AppData/Roaming. Rather
    // than track it down we just tell Tor where to put it.
    // PrintWriter printWriter = null;
    try (final PrintWriter confWriter = new PrintWriter(
        new BufferedWriter(new FileWriter(context.getTorrcFile(), true)))) {
      confWriter.println();
      confWriter.println(DIRECTIVE_COOKIE_AUTH_FILE + context.getCookieFile().getAbsolutePath());
      // For some reason the GeoIP's location can only be given as a file
      // name, not a path and it has
      // to be in the data directory so we need to set both
      confWriter.println(DIRECTIVE_DATA_DIRECTORY + context.getWorkingDirectory().getAbsolutePath());
      confWriter.println(DIRECTIVE_GEOIP_FILE + context.getGeoIpFile().getName());
      confWriter.println(DIRECTIVE_GEOIP6_FILE + context.getGeoIpv6File().getName());

      try (final BufferedReader in = new BufferedReader(
          new InputStreamReader(context.getAssetOrResourceByName(context.getPathToRC())))) {
        confWriter.println();
        String line = null;
        while ((line = in.readLine()) != null) {
          confWriter.println(line);
        }
      }
      if (!bridgeConfig.isEmpty()) {
        confWriter.println();
        confWriter.println("UseBridges 1");
      }
      for (final String bridgeLine : bridgeConfig) {
        confWriter.print("Bridge ");
        confWriter.println(bridgeLine);
      }

    }
  }

  private void setBrigeLines(final Collection<String> bridgeLines) throws IOException {
    if (bridgeLines == null) {
      return;
    }
    for (final String line : bridgeLines) {
      addBridgeLine(line);
    }

  }
}
