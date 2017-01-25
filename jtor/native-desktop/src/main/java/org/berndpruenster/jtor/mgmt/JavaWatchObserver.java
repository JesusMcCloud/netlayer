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

import java.io.File;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Watches to see if a particular file is changed
 */
class JavaWatchObserver implements WriteObserver {
  private final WatchService  watchService;
  private WatchKey            key;
  private final File          fileToWatch;
  private final long          lastModified;
  private final long          length;
  private static final Logger LOG = LoggerFactory.getLogger(WriteObserver.class);

  JavaWatchObserver(final File fileToWatch) throws IOException {
    if (fileToWatch == null || !fileToWatch.exists()) {
      throw new RuntimeException("fileToWatch must not be null and must already exist.");
    }
    this.fileToWatch = fileToWatch;
    lastModified = fileToWatch.lastModified();
    length = fileToWatch.length();

    watchService = FileSystems.getDefault().newWatchService();
    // Note that poll depends on us only registering events that are of type
    // path
    if (OsData.getOsType() != OsData.OsType.MACOS) {
      key = fileToWatch.getParentFile().toPath().register(watchService, StandardWatchEventKinds.ENTRY_CREATE,
          StandardWatchEventKinds.ENTRY_DELETE, StandardWatchEventKinds.ENTRY_MODIFY);
    } else {
      // Unfortunately the default watch service on MACOS is broken, it uses a
      // separate thread and really slow polling to detect file changes
      // rather than integrating with the OS. There is a hack to make it poll
      // faster which we can use for now. See
      // http://stackoverflow.com/questions/9588737/is-java-7-watchservice-slow-for-anyone-else
      key = fileToWatch.getParentFile().toPath().register(watchService,
          new WatchEvent.Kind[] { StandardWatchEventKinds.ENTRY_CREATE, StandardWatchEventKinds.ENTRY_DELETE,
              StandardWatchEventKinds.ENTRY_MODIFY });
    }
  }

  @Override
  public boolean poll(final long timeout, final TimeUnit unit) {
    boolean result = false;
    try {
      long remainingTimeoutInNanos = unit.toNanos(timeout);
      while (remainingTimeoutInNanos > 0) {
        final long startTimeInNanos = System.nanoTime();
        final WatchKey receivedKey = watchService.poll(remainingTimeoutInNanos, TimeUnit.NANOSECONDS);
        final long timeWaitedInNanos = System.nanoTime() - startTimeInNanos;

        if (receivedKey != null) {
          if (receivedKey != key) {
            throw new RuntimeException("This really shouldn't have happened. EEK!" + receivedKey.toString());
          }

          for (final WatchEvent<?> event : receivedKey.pollEvents()) {
            final WatchEvent.Kind<?> kind = event.kind();

            if (kind == StandardWatchEventKinds.OVERFLOW) {
              LOG.error("We got an overflow, there shouldn't have been enough activity to make that happen.");
            }

            final Path changedEntry = (Path) event.context();
            if (fileToWatch.toPath().endsWith(changedEntry)) {
              result = true;
              return result;
            }
          }

          // In case we haven't yet gotten the event we are looking for we have
          // to reset in order to
          // receive any further notifications.
          if (!key.reset()) {
            LOG.error("The key became invalid which should not have happened.");
          }
        }

        if (timeWaitedInNanos >= remainingTimeoutInNanos) {
          break;
        }

        remainingTimeoutInNanos -= timeWaitedInNanos;
      }

      // Even with the high sensitivity setting above for the MACOS the polling
      // still misses changes so I've added
      // a last modified check as a backup. Except I personally witnessed last
      // modified not returning a new value
      // value even when I saw the file change!!!! So I'm also adding in a
      // length check. Java really seems to
      // have an issue with the OS/X file system.
      result = (fileToWatch.lastModified() != lastModified) || (fileToWatch.length() != length);
      return result;
    } catch (final InterruptedException e) {
      throw new RuntimeException("Internal error has caused JavaWatchObserver to not be reliable.", e);
    } finally {
      if (result) {
        try {
          watchService.close();
        } catch (final IOException e) {
          LOG.debug("Attempt to close watchService failed.", e);
        }
      }
    }
  }
}
