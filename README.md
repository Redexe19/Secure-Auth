# SecureAuth — Minecraft 1.21.6, 1.21.7, 1.21.8

Server-side authentication for offline-mode Fabric servers. Players connect with unmodified vanilla clients.

## Requirements

- Minecraft 1.21.6, 1.21.7, 1.21.8
- Java >=21
- Fabric Loader >=0.18.1
- Fabric API; this project builds against `0.128.2+1.21.6`

## Use

Install SecureAuth and Fabric API on the server. New players register with `/register <password> <confirm>`; returning players use `/login <password>`. Unauthenticated players stay isolated in `secureauth:auth` until they authenticate. The chest-based auth panel is rendered by the vanilla client; players do not install SecureAuth.

Account records are stored in SQLite. Keep the SecureAuth database and configuration when updating the server.

## Build

Run `gradlew.bat build` on Windows or `./gradlew build` on Unix-like systems.
