package org.berndpruenster.netlayer.tor.demo;

import org.berndpruenster.netlayer.tor.HsContainer;
import org.berndpruenster.netlayer.tor.NativeTor;
import org.berndpruenster.netlayer.tor.Tor;
import org.berndpruenster.netlayer.tor.TorCtlException;

import java.io.File;
import java.io.IOException;
import java.util.Scanner;

public class JavaDemoProxy {

    public static void main(String[] args) throws TorCtlException, IOException {
        //set default instance, so it can be omitted whenever creating Tor (Server)Sockets
        //This will take some time
        Tor.setDefault(new NativeTor(/*Tor installation destination*/
                new File("tor-demo")));

        System.out.println("Tor has been bootstrapped");

        final HsContainer hsContainer = Tor.getDefault().publishHiddenService("hsDirName", 80, 8080);

        System.err.println("HiddenService coming up: " + hsContainer.getHostname());

        hsContainer.getHandler().attachHSReadyListener(hsContainer.getHostname(), () -> {
            System.err.println("HiddenService is online");
            return null;
        });

        System.err.println(
                "It will take some time for the HS to be reachable (up to 40 seconds). You will be notified about this");
        new Scanner(System.in).nextLine();
    }
}
