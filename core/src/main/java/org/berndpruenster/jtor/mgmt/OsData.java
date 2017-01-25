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

import java.io.IOException;
import java.util.Scanner;

public class OsData {
    public enum OsType { WIN, LNX32, LNX64, MACOS, ANDROID }
    private static OsType detectedType = null;

    public static OsType getOsType() {
        if (detectedType == null) {
            detectedType = actualGetOsType();
        }

        return detectedType;
    }

    /**
     * @return Type of OS we are running on
     */
    protected static OsType actualGetOsType() {

        //This also works for ART
        if (System.getProperty("java.vm.name").contains("Dalvik")) {
            return OsType.ANDROID;
        }

        final String osName = System.getProperty("os.name");
        if (osName.contains("Windows")) {
            return OsType.WIN;
        } else if (osName.contains("Mac")) {
            return OsType.MACOS;
        } else if (osName.contains("Linux")) {
            return getLinuxType();
        }
        throw new RuntimeException("Unsupported OS: "+osName);
    }

    protected static OsType getLinuxType() {
        final String [] cmd = { "uname", "-m" };
        Process unameProcess = null;
        try {
            String unameOutput;
            unameProcess = Runtime.getRuntime().exec(cmd);

            final Scanner scanner = new Scanner(unameProcess.getInputStream());
            if (scanner.hasNextLine()) {
                unameOutput = scanner.nextLine();
                scanner.close();
            } else {
                scanner.close();
                throw new RuntimeException("Couldn't get output from uname call");
            }

            final int exit = unameProcess.waitFor();
            if (exit != 0) {
                throw new RuntimeException("Uname returned error code " + exit);
            }

            if (unameOutput.matches("i.86")) {
                return OsType.LNX32;
            }
            if (unameOutput.compareTo("x86_64") == 0) {
                return OsType.LNX64;
            }
            throw new RuntimeException("Could not understand uname output, not sure what bitness");
        } catch (final IOException e) {
            throw new RuntimeException("Uname failure", e);
        } catch (final InterruptedException e) {
            throw new RuntimeException("Uname failure", e);
        } finally {

            if (unameProcess != null) {
                unameProcess.destroy();
            }
        }
    }
}
