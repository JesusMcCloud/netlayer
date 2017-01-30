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
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.channels.SocketChannel;
import java.util.Calendar;

import org.berndpruenster.jtor.mgmt.TorManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.runjva.sourceforge.jsocks.protocol.SocksSocket;

public class TorSocket extends Socket {

  private static final int    RETRY_SLEEP = 500;
  private static final Logger LOG         = LoggerFactory.getLogger(TorSocket.class);

  private final Socket        socket;

  public TorSocket(final TorManager mgr, final String endpoint, final int port) throws IOException {
    this(mgr, endpoint, port, 5, null);
  }

  public TorSocket(final TorManager mgr, final String endpoint, final int port, final String streamID)
      throws IOException {
    this(mgr, endpoint, port, 5, streamID);
  }

  public TorSocket(final TorManager mgr, final String endpoint, final int port, final int numTries) throws IOException {
    this(mgr, endpoint, port, numTries, null);
  }

  public TorSocket(final TorManager mgr, final String endpoint, final int port, final int numTries,
      final String streamID) throws IOException {
    this.socket = setupSocket(mgr, endpoint, port, numTries, streamID);
  }

  private SocksSocket setupSocket(final TorManager mgr, final String onionUrl, final int port, final int numTries,
      final String streamID) throws IOException {
    final long before = Calendar.getInstance().getTimeInMillis();
    for (int i = 0; i < numTries; ++i) {
      try {
        LOG.debug("trying to connect to  " + onionUrl + ":" + port);
        final SocksSocket ssock = new SocksSocket(mgr.getProxy(streamID), onionUrl, port);

        LOG.debug("Took " + (Calendar.getInstance().getTimeInMillis() - before) + " milliseconds to connect to "
            + onionUrl + ":" + port);
        ssock.setTcpNoDelay(true);
        return ssock;
      } catch (final UnknownHostException exx) {
        try {
          LOG.debug("Try " + (i + 1) + " connecting to " + onionUrl + ":" + port + " failed. retrying...");
          Thread.sleep(RETRY_SLEEP);
          continue;
        } catch (final InterruptedException e) {
        }
      } catch (final Exception e) {
        throw new IOException("Cannot connect to hidden service");
      }
    }
    throw new IOException("Cannot connect to hidden service");
  }

  @Override
  public void connect(final SocketAddress arg0) throws IOException {
    socket.connect(arg0);
  }

  @Override
  public void connect(final SocketAddress arg0, final int arg1) throws IOException {
    socket.connect(arg0, arg1);
  }

  @Override
  public void bind(final SocketAddress arg0) throws IOException {
    socket.bind(arg0);
  }

  @Override
  public InetAddress getInetAddress() {
    return socket.getInetAddress();
  }

  @Override
  public InetAddress getLocalAddress() {
    return socket.getLocalAddress();
  }

  @Override
  public int getPort() {
    return socket.getPort();
  }

  @Override
  public int getLocalPort() {
    return socket.getLocalPort();
  }

  @Override
  public SocketAddress getRemoteSocketAddress() {
    return socket.getRemoteSocketAddress();
  }

  @Override
  public SocketAddress getLocalSocketAddress() {
    return socket.getLocalSocketAddress();
  }

  @Override
  public SocketChannel getChannel() {
    return socket.getChannel();
  }

  @Override
  public InputStream getInputStream() throws IOException {
    return socket.getInputStream();
  }

  @Override
  public OutputStream getOutputStream() throws IOException {
    return socket.getOutputStream();
  }

  @Override
  public void setTcpNoDelay(final boolean arg0) throws SocketException {
    socket.setTcpNoDelay(arg0);
  }

  @Override
  public boolean getTcpNoDelay() throws SocketException {
    return socket.getTcpNoDelay();
  }

  @Override
  public void setSoLinger(final boolean arg0, final int arg1) throws SocketException {
    socket.setSoLinger(arg0, arg1);
  }

  @Override
  public int getSoLinger() throws SocketException {
    return socket.getSoLinger();
  }

  @Override
  public void sendUrgentData(final int arg0) throws IOException {
    socket.sendUrgentData(arg0);
  }

  @Override
  public void setOOBInline(final boolean arg0) throws SocketException {
    socket.setOOBInline(arg0);
  }

  @Override
  public boolean getOOBInline() throws SocketException {
    return socket.getOOBInline();
  }

  @Override
  public synchronized void setSoTimeout(final int arg0) throws SocketException {
    socket.setSoTimeout(arg0);
  }

  @Override
  public synchronized int getSoTimeout() throws SocketException {
    return socket.getSoTimeout();
  }

  @Override
  public synchronized void setSendBufferSize(final int arg0) throws SocketException {
    socket.setSendBufferSize(arg0);
  }

  @Override
  public synchronized int getSendBufferSize() throws SocketException {
    return socket.getSendBufferSize();
  }

  @Override
  public synchronized void setReceiveBufferSize(final int arg0) throws SocketException {
    socket.setReceiveBufferSize(arg0);
  }

  @Override
  public synchronized int getReceiveBufferSize() throws SocketException {
    return socket.getReceiveBufferSize();
  }

  @Override
  public void setKeepAlive(final boolean arg0) throws SocketException {
    socket.setKeepAlive(arg0);
  }

  @Override
  public boolean getKeepAlive() throws SocketException {
    return socket.getKeepAlive();
  }

  @Override
  public void setTrafficClass(final int arg0) throws SocketException {
    socket.setTrafficClass(arg0);
  }

  @Override
  public int getTrafficClass() throws SocketException {
    return socket.getTrafficClass();
  }

  @Override
  public void setReuseAddress(final boolean arg0) throws SocketException {
    socket.setReuseAddress(arg0);
  }

  @Override
  public boolean getReuseAddress() throws SocketException {
    return socket.getReuseAddress();
  }

  @Override
  public synchronized void close() throws IOException {
    socket.close();
  }

  @Override
  public void shutdownInput() throws IOException {
    socket.shutdownInput();
  }

  @Override
  public void shutdownOutput() throws IOException {
    socket.shutdownOutput();
  }

  @Override
  public String toString() {
    return socket.toString();
  }

  @Override
  public boolean isConnected() {
    return socket.isConnected();
  }

  @Override
  public boolean isBound() {
    return socket.isBound();
  }

  @Override
  public boolean isClosed() {
    return socket.isClosed();
  }

  @Override
  public boolean isInputShutdown() {
    return socket.isInputShutdown();
  }

  @Override
  public boolean isOutputShutdown() {
    return socket.isOutputShutdown();
  }

  @Override
  public void setPerformancePreferences(final int arg0, final int arg1, final int arg2) {
    socket.setPerformancePreferences(arg0, arg1, arg2);
  }

}
