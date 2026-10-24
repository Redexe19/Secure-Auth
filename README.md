# SecureAuth — Minecraft 1.20.2

Server-side authentication for offline-mode Fabric servers. Players use an unmodified vanilla client.

## Requirements

- Minecraft 1.20.2
- Java 17
- Fabric Loader 0.15.11 or newer
- Fabric API matching Minecraft 1.20.2 (the project builds against 0.91.6+1.20.2)

## Use

Install this jar and Fabric API on the server. Players create accounts with `/register` and return with `/login`; unauthenticated players remain quarantined until they authenticate. The chest-based auth panel works with vanilla clients.

SQLite account storage and the SecureAuth configuration are shared by the SecureAuth Minecraft ports. Back up the server's SecureAuth data before changing server software.

## Build

Run `gradlew.bat build` on Windows or `./gradlew build` on Unix-like systems.
