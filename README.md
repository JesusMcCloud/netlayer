# NetLayer
> Come for the Proxy, stay for the Tor Bindings

This repository currently contains a Kotlin/Java8 Tor Library supporting
 * Tunnelling traffic through Tor using a custom Socket implementation
 * Stream isolation
 * Bridges and pluggable transports
 * Connecting to hidden services
 * Hosting of hidden services
 
 This project was originally based on a [previous fork](https://github.com/ManfredKarrer/Tor_Onion_Proxy_Library
) of [thaliproject/Tor_Onion_Proxy_Library](https://github.com/thaliproject/Tor_Onion_Proxy_Library), but deviated significatnly since.

## Usage
This is essentially a Wrapper around the official Tor releases, pre-packaged for easiy use and convenient integration into Kotlin/Java Projects.
As of you, simply add `tor.native` as dependency to your project (using JitPack):
```XML
    <repositories>
    <repository>
        <id>jitpack.io</id>
        <url>https://jitpack.io</url>
    </repository>
    </repositories>
```
```XML
      <dependency>
          <groupId>com.github.JesusMcCloud.netlayer</groupId>
          <artifactId>tor.native</artifactId>
          <version>${netlayer.version}</version>
      </dependency>
```


### Tunneling Traffic through Tor
This library provides a plain TCP socket which can be used like any other:

#### Kotlin
```Kotlin
    //set default instance, so it can be omitted whenever creating Tor (Server)Sockets
    //This will take some time
    Tor.default = NativeTor(/*Tor installation destination*/ File("tor-demo"))
    TorSocket("www.google.com", 80, streamId = "FOO" /*this one is optional*/) //clear web
    TorSocket("facebookcorewwwi.onion", 443, streamId = "BAR") //hidden service
```

#### Java
```Java
    //set default instance, so it can be omitted whenever creating Tor (Server)Sockets
    //This will take some time
    Tor.setDefault(new NativeTor(/*Tor installation destination*/ new File("tor-demo")));
    new TorSocket("www.google.com", 80, "FOO");
    new TorSocket("facebookcorewwwi.onion", 443, "BAR");
```

### Using Bridges and Pluggable Transports
To use bridges, simply pass the contents of a bridge configuration obtained from https://bridges.torproject.org/ (line-by-line wrapped in a *Collection*) as second parameter to the constructor of the `NativeTor` class.

### Hosting Hidden Services
Hidden services can be hosted by creating a torified `ServerSocket`.

#### Kotlin
```Kotlin
    //create a hidden service in directory 'test' inside the tor installation directory
    HiddenServiceSocket(8080, "test")
    //optionally attack a ready listener to be notified as soon as the service becomes reachable
    hiddenServiceSocket.addReadyListener { socket -> /*your code here*/}
```

#### Java
```Java
    //create a hidden service in directory 'test' inside the tor installation directory
    HiddenServiceSocket hiddenServiceSocket = new HiddenServiceSocket(8080, "test");
    //it takes some time for a hidden service to be ready, so adding a listener only after creating the HS is not an issue
    hiddenServiceSocket.addReadyListener(socket -> { /*your code here*/ return null});
```

## Verifying the Authenticity/Integrity of the Tor Distribution
This library ships the official Tor binaries. To verify their authenticity, simply rebuild [the prepackaged Tor binaries](https://github.com/JesusMcCloud/tor-binary) (courtesy of [cedric walter](https://github.com/cedricwalter)) and rebuild the `tor.native`
