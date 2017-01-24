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

import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.berndpruenster.jtor.socket.HiddenServiceSocket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.freehaven.tor.control.EventHandler;

/**
 * Logs the data we get from notifications from the Tor OP. This is really just
 * meant for debugging.
 */
public class TorEventHandler implements EventHandler {

  private static final String                                 UPLOADED = "UPLOADED";
  private static final String                                 HS_DESC  = "HS_DESC";
  private static final Logger                                 LOG      = LoggerFactory.getLogger(TorEventHandler.class);

  private final Map<String, HiddenServiceSocket>              socketMap;
  private final Map<String, List<HiddenServiceReadyListener>> listenerMap;

  TorEventHandler() {
    this.socketMap = new HashMap<>();
    this.listenerMap = new HashMap<>();
  }

  public void attachReadyListeners(final HiddenServiceSocket hs, final List<HiddenServiceReadyListener> listeners) {
    synchronized (socketMap) {
      socketMap.put(hs.getServiceName(), hs);
      listenerMap.put(hs.getServiceName(), listeners);
    }
  }

  @Override
  public void circuitStatus(final String status, final String id, final String path) {
    final String msg = "CircuitStatus: " + id + " " + status + ", " + path;
    LOG.debug(msg);
  }

  @Override
  public void streamStatus(final String status, final String id, final String target) {
    final String msg = "streamStatus: status: " + status + ", id: " + id + ", target: " + target;
    LOG.debug(msg);

  }

  @Override
  public void orConnStatus(final String status, final String orName) {
    final String msg = "OR connection: status: " + status + ", orName: " + orName;
    LOG.debug(msg);
  }

  @Override
  public void bandwidthUsed(final long read, final long written) {
    LOG.debug("bandwidthUsed: read: " + read + ", written: " + written);
  }

  @Override
  public void newDescriptors(final List<String> orList) {
    final Iterator<String> iterator = orList.iterator();
    final StringBuilder stringBuilder = new StringBuilder();
    while (iterator.hasNext()) {
      stringBuilder.append(iterator.next());
    }
    final String msg = "newDescriptors: " + stringBuilder.toString();
    LOG.debug(msg);

  }

  @Override
  public void message(final String severity, final String msg) {
    final String msg2 = "message: severity: " + severity + ", msg: " + msg;
    LOG.debug(msg2);
  }

  @Override
  public void unrecognized(final String type, final String msg) {
    final String msg2 = "unrecognized: type: " + type + ", msg: " + msg;
    LOG.debug(msg2);
    if (type.equals(HS_DESC) && msg.startsWith(UPLOADED)) {
      final String hiddenServiceID = msg.split(" ")[1] + ".onion";
      synchronized (socketMap) {
        final HiddenServiceSocket hs = socketMap.get(hiddenServiceID);
        if (hs == null) {
          return;
        }
        LOG.info("Hidden Service " + hs + " is ready");
        for (final HiddenServiceReadyListener listener : listenerMap.get(hiddenServiceID)) {
          listener.onReady(hs);
        }
        socketMap.remove(hiddenServiceID);
        listenerMap.remove(hiddenServiceID);
      }
    }
  }

}
