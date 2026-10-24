# SecureAuth — Minecraft 1.20.3 and 1.20.4

Server-side authentication for offline-mode Fabric servers. Players use an unmodified vanilla client.

## Requirements

- Minecraft 1.20.3 or 1.20.4
- Java 17
- Fabric Loader 0.15.11 or newer
- Fabric API matching the server's Minecraft version

The project builds against Fabric API 0.91.1+1.20.3 and 0.97.3+1.20.4.

## Use

Install this jar and the matching Fabric API on the server. Players create accounts with `/register` and return with `/login`; unauthenticated players remain quarantined until they authenticate. The chest-based auth panel works with vanilla clients.

SQLite account storage and the SecureAuth configuration are shared by the SecureAuth Minecraft ports. Back up the server's SecureAuth data before changing server software.

## Build

Run `gradlew.bat build` on Windows or `./gradlew build` on Unix-like systems.
