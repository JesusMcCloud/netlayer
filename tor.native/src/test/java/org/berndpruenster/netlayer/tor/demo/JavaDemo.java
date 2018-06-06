package org.berndpruenster.netlayer.tor.demo;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import org.berndpruenster.netlayer.tor.*;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Scanner;

public class JavaDemo {
    @Parameter(names = {"-b"},
               description = "path to a file containing bridge configuration lines as obtainable from bridges.torproject.org")
    private String pathBridges;

    @Parameter(names = {"-p"}, description = "hidden Service Port")
    private int port;

    public static void main(String[] args) throws IOException, TorCtlException {
        JavaDemo demo = new JavaDemo();
        demo.port = 10024;
        new JCommander(demo).parse();


        //set default instance, so it can be omitted whenever creating Tor (Server)Sockets
        //This will take some time
        Tor.setDefault(new NativeTor(/*Tor installation destination*/
                new File("tor-demo"),
                /*bridge configuration*/ parseBridgeLines(demo.pathBridges)));

        System.out.println("Tor has been bootstrapped");

        //create a hidden service in directory 'test' inside the tor installation directory
        HiddenServiceSocket hiddenServiceSocket = new HiddenServiceSocket(demo.port, "test");

        //it takes some time for a hidden service to be ready, so adding a listener only after creating the HS is not an issue
        hiddenServiceSocket.addReadyListener(socket -> {
            System.out.println("Hidden Service " + socket + " is ready");
            new Thread(() -> {
                System.err.println("we'll try and connect to the just-published hidden service");
                try {
                    new TorSocket(socket.getSocketAddress(), "Foo");
                    System.err.println("Connected to $socket. closing socket...");
                    socket.close();
                } catch (Exception e) {
                    System.err.println("This should have worked");
                }
                //retry connecting
                try {

                    new TorSocket(socket.getServiceName(), socket.getHiddenServicePort(), "Foo");
                } catch (Exception e) {
                    System.err.println("As exptected, connection to " + socket + " failed!");
                }
                try {
                    //let's connect to some regular domains using different streams
                    new TorSocket("www.google.com", 80, "FOO");
                    new TorSocket("www.cnn.com", 80, "BAR");
                    new TorSocket("www.google.com", 80, "BAZ");
                } catch (Exception e) {
                    System.err.println("This should have worked");
                }

                System.exit(0);

            }).start();
            try {
                socket.accept();
            } catch (IOException e) {
                e.printStackTrace();
            }
            System.err.println("$socket got a connection");

            return null;
        });
        System.err.println(
                "It will take some time for the HS to be reachable (up to 40 seconds). You will be notified about this");
        new Scanner(System.in).nextLine();
    }


    private static Collection<String> parseBridgeLines(String file) throws IOException {
        if (file == null) {
            return null;
        }
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String       line  = null;
            List<String> lines = new LinkedList<>();
            while ((line = reader.readLine()) != null) {
                lines.add(line);
            }
            return lines;
        } catch (IOException e) {
            throw e;
        }
    }

}
