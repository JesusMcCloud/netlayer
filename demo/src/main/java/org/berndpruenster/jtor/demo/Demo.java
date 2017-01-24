package org.berndpruenster.jtor.demo;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.net.Socket;
import java.util.Collection;
import java.util.LinkedList;
import java.util.Scanner;

import org.berndpruenster.jtor.mgmt.HiddenServiceReadyListener;
import org.berndpruenster.jtor.mgmt.JavaTorManager;
import org.berndpruenster.jtor.mgmt.TorManager;
import org.berndpruenster.jtor.socket.HiddenServiceSocket;
import org.berndpruenster.jtor.socket.TorSocket;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;

public class Demo {

  @Parameter(names = "-b", description = "path to a file containing bridge configuration lines as obtainable from bridges.torproject.org")
  private String pathBridges;

  @Parameter(names = "-p", description = "hidden Service Port")
  private int    port;

  public static void main(final String[] args) throws IOException {
    final Demo demo = new Demo();
    demo.port = 10024;
    new JCommander(demo, args);

    final TorManager mgr = new JavaTorManager(new File("tor"), true);
    if (demo.pathBridges != null) {
      mgr.setBrigeLines(parseBridgeLines(demo.pathBridges));
    }
    mgr.bootstrap();

    final HiddenServiceSocket hiddenServiceSocket = new HiddenServiceSocket(mgr, demo.port, "test");
    hiddenServiceSocket.addReadyListener(new HiddenServiceReadyListener() {

      @Override
      public void onReady(final HiddenServiceSocket socket) {
        Socket con;
        try {
          System.err.println("Hidden Service " + socket + " is ready");
          new Thread() {
            @Override
            public void run() {
              try {
                new TorSocket(mgr, hiddenServiceSocket.getServiceName(), hiddenServiceSocket.getHiddenServicePort());
                System.err.println("Connected to " + hiddenServiceSocket + ". exiting...");

              } catch (final IOException e1) {
                e1.printStackTrace();
              }
              System.exit(0);
            }
          }.start();
          con = socket.accept();
          System.err.println(socket + " got a connection");

        } catch (final IOException e) {
          e.printStackTrace();
        }
      }
    });
    System.err
        .println("It will take some time for the HS to be reachable (~40 seconds). You will be notified about this");
    new Scanner(System.in).nextLine();

  }

  private static Collection<String> parseBridgeLines(final String file) throws FileNotFoundException, IOException {
    try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
      final LinkedList<String> lines = new LinkedList<>();
      String line;
      while ((line = reader.readLine()) != null) {
        lines.add(line);
      }
      return lines;
    }
  }

}
