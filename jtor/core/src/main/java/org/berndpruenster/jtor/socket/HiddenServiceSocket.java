/*
Copyright 2017, Bernd Prünster <mail@berndpruenster.org>

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

It is based on the Tor_Onion_Proxy_Library
(github.com/thaliproject/Tor_Onion_Proxy_Library) licensed under the
Apache License, Version 2.0 and also includes software developed by the Tor
Project (www.torproject.org) licensed under the BSD License.
*/
package org.berndpruenster.jtor.socket;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.SocketAddress;
import java.util.LinkedList;
import java.util.List;
import java.util.Map.Entry;

import org.berndpruenster.jtor.mgmt.HiddenServiceReadyListener;
import org.berndpruenster.jtor.mgmt.TorCtlException;
import org.berndpruenster.jtor.mgmt.TorEventHandler;
import org.berndpruenster.jtor.mgmt.TorManager;

public class HiddenServiceSocket extends ServerSocket {

  private final String                           hiddenServiceDirectory;
  private final int                              hiddenServicePort;
  private final String                           serviceName;
  private final TorManager                       mgr;
  private final List<HiddenServiceReadyListener> listeners;

  public String getServiceName() {
    return serviceName;
  }

  public HiddenServiceSocket(final TorManager mgr, final int port, final String hsDir)
      throws IOException, TorCtlException {
    this(mgr, port, port, hsDir);
  }

  public HiddenServiceSocket(final TorManager mgr, final int localPort, final int hiddenServicePort, final String hsDir)
      throws IOException, TorCtlException {
    super();
    this.mgr = mgr;
    this.listeners = new LinkedList<>();
    final Entry<String, TorEventHandler> helper = mgr.publishHiddenService(hsDir, hiddenServicePort, localPort);
    this.serviceName = helper.getKey();
    this.hiddenServiceDirectory = hsDir;
    this.hiddenServicePort = hiddenServicePort;
    bind(new InetSocketAddress(TorManager.LOCAL_IP, localPort));
    helper.getValue().attachReadyListeners(this, listeners);
  }

  public void addReadyListener(final HiddenServiceReadyListener listener) {
    synchronized (listeners) {
      listeners.add(listener);
    }
  }

  public int getHiddenServicePort() {
    return hiddenServicePort;
  }

  String getHiddenServiceDirectory() {
    return hiddenServiceDirectory;
  }

  public SocketAddress getHiddenServiceSocketAddress() {
    return new HiddenServiceSocketAddress(serviceName, hiddenServicePort);
  }

  @Override
  public String toString() {
    return new StringBuilder(serviceName).append(":").append(hiddenServicePort).append(":").append(getLocalPort())
        .toString();
  }

  @Override
  public void close() throws IOException {
    super.close();
    try {
      mgr.unpublishHiddenService(getHiddenServiceDirectory());
    } catch (final TorCtlException e) {
      throw new IOException(e);
    }
  }

}
