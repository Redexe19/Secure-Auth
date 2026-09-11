<img width="2048" height="810" alt="bannerorthumbnail" src="https://github.com/user-attachments/assets/cbcc9f65-c3fe-4e9c-acc0-08a03ebc4def" />


**Server-side authentication for offline-mode Minecraft 26.2 Fabric servers.**

![Minecraft](https://img.shields.io/badge/Minecraft-26.2-62b47a) ![Fabric](https://img.shields.io/badge/Fabric%20Loader-0.19.5%2B-dbba52) ![Java](https://img.shields.io/badge/Java-25-f89820) ![License](https://img.shields.io/badge/License-MIT-3da639) ![Mode](https://img.shields.io/badge/server--side--only-4ec9b0)

SecureAuth turns "logged in" into a **server-side state transition** instead of a chat command
that the server politely believes. Unauthenticated players are physically moved into a
dedicated quarantine dimension — a sealed bedrock holding cell inside a pure void — their
movement is corrected every tick, world interaction, chat and commands are blocked at the
packet level, and information about other players and the real world is never synced to
their client. Accounts are stored in a transactional SQLite database with Argon2id password
hashes, wrapped in four independent brute-force protection layers and a structured,
rotating security log.

The mod is **server-side only** (`environment: "server"`): there is no client mod, no custom
packets and no companion handshake. Players join with completely unmodified vanilla clients
and authenticate through chat commands plus a server-built **chest panel** that vanilla
clients render as an ordinary chest menu.

> [!TIP]
> Looking for the deep documentation? **[WIKI.md](https://github.com/Redexe19/Secure-Auth/wiki)** is the full wiki — every
> command, every config key, the auth state machine, the sandbox internals, the security
> events reference, FAQ and troubleshooting.

## 1.0.0 — first stable release

This is the first public release. Everything below is the complete, verified feature set:

- **Dimension quarantine with a sealed bedrock cell.** Unauthenticated players are moved
  into `secureauth:auth` — an overworld-style void (flat-air generation, no features, no
  spawners, re-seeded with a fresh random seed every boot and wiped on every restart) —
  and held inside a hollow bedrock box (7×7 interior, 3 blocks of head room, no
  suffocation, nothing to fall off, nothing to dig through).
- **Total sensory lockdown while waiting.** Infinite ambient blindness (thick fog), a
  1.5-block movement leash with a 2 Hz authoritative position re-sync, adventure mode so
  the vanilla client itself refuses interaction, all damage cancelled inside the sandbox,
  and full information isolation (tab list, chat broadcasts, maps, scoreboard, command
  tree).
- **Symmetric, verified release.** On login/register the player is restored to the exact
  pre-quarantine snapshot (dimension, position, rotation, game mode, flags), the tab
  list repopulates immediately (vanilla's own join packet, including the `listed` bit),
  scoreboards and held maps are re-sent, and the sandbox state never leaks into the
  player's save data.
- **Nobody stays behind.** A 5-second release watchdog auto-rescues any authenticated
  player still stuck inside the dimension (lag-failed transfers re-checked every
  second); a trusted same-IP rejoin whose save still points into the void is rescued
  before it can fall; and the mirror-image **ability reconciliation** repairs, within
  one second, any sandbox restriction (adventure game type, blindness,
  invulnerable/no-gravity) still stuck on a player who is *outside* the dimension —
  no more "logged in but can't break blocks".
- **Self-healing storage.** The SQLite account store closes, reopens and retries a
  failed transaction once, probes its own health every 30 seconds, and every failure
  is journaled with its exact root cause — the flaky "authentication service is
  unavailable" class of failure is gone.
- **Argon2id passwords, four brute-force layers, structured security log**, a
  12-hour server-side session-resume window, and vanilla-compatible chest GUIs for
  players and admins.

<details>
<summary><strong>Development history (pre-release builds)</strong></summary>

Before this 1.0.0 release the mod went through internal development builds
(1.1.x–1.2.4) that were never published. They are the reason 1.0.0 ships this
hardened:

- **1.1.x** — message & sandbox repair, hashed session tokens replaced by the
  server-side session resume, chest panels reworked.
- **1.2.0** — overworld-style void sandbox, action-bar timer, 12-hour sessions.
- **1.2.1** — guaranteed pure void: datapack biome with empty spawners, entity
  birth guard mixin, self-healing block purifier.
- **1.2.2** — total sensory lockdown (blindness, adventure lock, 2 Hz re-sync,
  fresh dimension + fresh seed every boot, platform moved to y=200).
- **1.2.3** — clean release after login: tab list repopulates via vanilla's own
  join packet, no floating/invulnerable save residue (self-heals poisoned saves),
  deterministic disconnect repair, scoreboard + map re-send.
- **1.2.4** — sealed bedrock cell, 5 s release watchdog, damage-free sandbox,
  self-healing SQLite store, `/auth reset` hardening.

</details>

## Table of contents

1. [Why SecureAuth exists](#why-secureauth-exists)
2. [Security model](#security-model)
3. [Security disclaimer (read this)](#security-disclaimer-read-this)
4. [Requirements and installation](#requirements-and-installation)
5. [Building from source](#building-from-source)
6. [Configuration reference](#configuration-reference)
7. [Commands and permissions](#commands-and-permissions)
8. [Chest auth panel (vanilla clients)](#chest-auth-panel-vanilla-clients)
9. [Architecture overview](#architecture-overview)
10. [Verification checklist](#verification-checklist)
11. [Troubleshooting and FAQ](#troubleshooting-and-faq)
12. [License](#license)

---

## Why SecureAuth exists

Offline-mode servers (`online-mode=false` in `server.properties`) skip Mojang/Microsoft
identity verification entirely. Anyone who knows a player's name can connect as that player.
The classic answer is a chat-plugin: the player types `/login hunter2`, the plugin compares
the password and — crucially — *believes the player* from then on. Until that moment the
player has already been fully loaded into the world: the server has streamed chunks,
entities, tile entities, the tab list, the scoreboard and the full command tree to a
connection that has proven nothing.

That is the gap SecureAuth closes. Authentication is a **state machine the server owns**:

```
UNREGISTERED → REGISTERING → REGISTERED_NOT_AUTHENTICATED → AUTHENTICATED
                                     │
                                     └─ too many failures ──► LOCKED
```

A player in any state other than `AUTHENTICATED`:

- is **not in the real world at all** (moved to the `secureauth:auth` quarantine dimension
  by default, or frozen in place in fallback mode),
- cannot move beyond a 1.5-block drift radius (server-side position correction every tick
  plus a 2 Hz authoritative re-sync to the platform),
- cannot break, place, use, attack, drop, pick up or open anything (and adventure mode
  makes the vanilla client itself refuse interaction),
- cannot chat and cannot run any command outside the SecureAuth command roots
  (`register`, `login`, `logout`, `changepassword`, `unregister`, `auth`),
- does not receive other players' tab-list entries, chat broadcasts, map data or the real
  command tree,
- cannot be hurt by anything inside the sandbox (all damage is cancelled there),
- is disconnected automatically after a configurable timeout.

Only a successful password verification (or a matching server-side **session resume** record,
see below) performs the state transition to `AUTHENTICATED`, restores the player from a
server-side snapshot of their original dimension, position, rotation and game mode, and lifts
every restriction at once. If the account database cannot be read, the player stays
quarantined — the mod **fails closed**, never open.

The auth UX is deliberately ordinary: a chat prompt (`/login <password>`) plus a chest panel
the server builds out of vanilla items. No custom packets, no client mod, nothing a modified
client can negotiate around — a hostile client can ignore the panel, macro-click it or render
it wrong, and none of that changes the server's state machine. Only the server's own state
decides what an unauthenticated connection may see and do.

---

## Security model

### The auth state machine

```
                         ┌───────────────────────────────┐
                         │      player joins server      │
                         └───────────────┬───────────────┘
                                         │  (per-IP join limiter first;
                                         │   over limit => disconnected)
                                         ▼
                            ┌────────────────────────┐
        account exists ──── │      UNREGISTERED      │ ◄── account deleted
             no │           └───────────┬────────────┘      (/unregister,
                │                       │ /register <pw>    /auth unregister)
                │                       │ <pw> (policy-checked,
                │                       │  hashed, stored)
                │                       ▼
                │              ┌──────────────────┐
                │              │    REGISTERING    │
                │              └────────┬─────────┘
                │        auto-login off │      auto-login on
                │                       ▼      │
                │   ┌───────────────────┐      │
                └──►│ REGISTERED_NOT_   │◄─────┘──── /logout (re-quarantine,
                    │ AUTHENTICATED     │              fresh snapshot, prompt)
                    └───┬─────────┬─────┘
        /login <pw> ────┘         └──── failures ≥ maxLoginAttempts
        or session resume                │
        (same-IP window)                 ▼
                │              ┌───────────────┐   permanentLockAfter
                │              │    LOCKED     │◄─ RepeatedLockouts, or
                │              │ (temporary or │  /auth lock (permanent)
                │              │  permanent)   │
                │              └───────┬───────┘
                │                      │ lockout expires / /auth unlock
                │◄─────────────────────┘
                ▼
      ┌─────────────────────┐
      │    AUTHENTICATED    │  snapshot restored: dimension, position,
      │ (sandbox lifted in  │  rotation, game mode; info isolation off;
      │  one transition)    │  optional session-resume window opened
      └─────────────────────┘
```

The state lives exclusively in the server's per-connection `AuthSession`. The client is
never asked — and never allowed — to report its own authentication state.

### The pre-auth sandbox

| Layer | Mechanism | Default |
|---|---|---|
| Dimension isolation | Player teleported into `secureauth:auth` — an overworld-style void (blue sky, day cycle, `features: false` flat generation) whose only blocks are the mod-placed sealed bedrock holding cell (7×7 hollow interior, 3 blocks head room) — original location snapshotted server-side and restored on success | `worldProtection.isolationMode: auth_dimension` |
| Fallback isolation | If the dimension is missing or the mode is set to `freeze_in_place`: player stays put but is immobilised, invulnerable, filtered and command-blocked — fail-closed, never "let them wander" | `freeze_in_place` |
| Holding cell | The platform is a **bedrock box**: floor, walls and ceiling are bedrock (`platformBlock` default), the player is *inside* it — no falling off, no digging out, no suffocating | `worldProtection.platformBox: true` |
| Movement | `ServerboundMovePlayerPacket` (and vehicle movement) handling is cancelled while unauthenticated; the manager corrects position every tick (drift beyond `maxDriftBlocks` → teleport back to the platform), re-syncs the authoritative platform position twice per second and re-quarantines dimension escapes | `worldProtection.movementCorrection: true` |
| Adventure lock | The quarantined player is switched to adventure mode, so the vanilla client itself refuses to break/place/interact (client-side prediction can no longer make it *look* possible) | on |
| Blindness | Infinite ambient blindness (thick fog, no particles) re-applied once per second — whatever a modified client could still render of the dimension is simply not visible | `worldProtection.quarantineBlindness: true` |
| Damage immunity | ALL damage inside the auth dimension is cancelled and fall distance reset — the sandbox is a waiting room, not a hazard | `worldProtection.noDamageInSandbox: true` |
| Block interaction | Block break, block use, item use, entity attack and entity use cancelled (Fabric interaction events + server mixins) | `worldProtection.blockInteraction: true` |
| Items | Item pickup (`playerTouch`) and drops/swap (`ServerboundPlayerActionPacket`) blocked | on |
| Containers | `ServerboundContainerClickPacket` blocked — inventory and container clicks, including clicks on the auth panel's own grid (see [chest auth panel](#chest-auth-panel-vanilla-clients)) | on |
| Chat | `ALLOW_CHAT_MESSAGE` denies all chat from unauthenticated connections | `worldProtection.blockChat: true` |
| Commands | Every command except the SecureAuth roots `register`, `login`, `logout`, `changepassword`, `unregister`, `auth` is cancelled before execution; logged (scrubbed) | `worldProtection.blockCommands: true` |
| Entity hygiene | Non-player entities that end up in the auth dimension are refused at birth (mixin guard) and swept away periodically | `worldProtection.clearAuthEntities: true` |
| Void purity | Any block that is not part of the holding cell is removed from loaded chunks (budgeted sweep once per second) | `worldProtection.pureVoid: true` |
| Fresh dimension | Every restart: chunk files wiped, seed re-randomised (never the overworld seed) | `worldProtection.resetOnRestart: true` |
| Timeout | Action-bar countdown (or periodic chat warnings when `ui.actionBarTimer: false`), then disconnect | `authentication.timeoutSeconds: 60` |

### Release guarantees (nobody stays behind)

Authentication is only done when the player is *physically back in the real world* with
*every restriction lifted*. Four mechanisms make that true even under extreme server lag
or entity-recreation races (a cross-dimension transfer can silently replace the
`ServerPlayer` entity — a naive one-shot restore then acts on a ghost):

1. **Stale-removal repair** — before every teleport the mod clears the half-finished
   transfer flag that makes `ServerPlayer.teleport()` silently no-op, and the session
   re-binds itself to the live entity every tick.
2. **Release watchdog** — an authenticated player still inside the auth dimension
   `releaseWatchdogSeconds` (5 s default) after login is automatically rescued back to
   their snapshot (or respawn anchor), re-checked every second until the transfer
   sticks, with a player notice and a `release_watchdog_rescued` security event.
3. **Trusted-rejoin rescue** — a same-IP session-resume join whose save data still
   points into the auth dimension (the player disconnected while a release was pending)
   is moved out immediately, before they can fall anywhere, and fall distance is reset.
4. **Ability reconciliation** — the mirror image: an authenticated player who is
   *outside* the auth dimension but still carrying sandbox restrictions (adventure game
   type, the mod's blindness signature, the invulnerable+no-gravity pair — exactly what
   a restore that missed the live entity looks like, "tab list came back but I can't
   break blocks") is repaired within one second. The game-type truth is the
   pre-quarantine snapshot, or — for a session-resume join, which has no snapshot —
   the auth-time game type the resume record remembered (and then only with a
   corroborating sandbox signature, so operator changes are never fought). The check
   is one-shot per quarantine, so later operator game-mode changes are never
   fought. Repairs are logged (`restricted_outside_sandbox; abilities_restored`).

### Information isolation (what an unauthenticated client never sees)

- **Tab list**: other players are removed from the viewer's tab list (`ClientboundPlayerInfoUpdate/Remove/TabList` filtered).
- **Chat broadcasts**: system chat, player chat and disguised chat (join/leave/advancement/server messages) are dropped for unauthenticated viewers.
- **Maps**: map data packets are dropped.
- **Command tree**: the client receives a minimal auth-only command tree (the `register`, `login` and `auth` literals) instead of the full server command tree — this is also a reconnaissance countermeasure (no plugin/mod command enumeration).
- **Scoreboard and custom payloads**: other mods' payloads optionally filtered (off by default, may break other mods).
- SecureAuth's own feedback (prompts, panel updates, tab-list hiding itself) is sent through a thread-local bypass so the outgoing filter can never drop it. All of it is ordinary vanilla packets — chat components, chest menu opens and container content syncs — which is exactly why unmodified clients work.

### Fail-closed design

- No session for a connection ⇒ treated as unauthenticated (never trusted by default).
- Database unreadable at join ⇒ the session is created anyway, the player is quarantined, and logins fail with a storage error until the database recovers (the store also self-heals — see below).
- Argon2 unavailable and stored hash is Argon2 ⇒ verification fails (no downgrade attack).
- Panel click abuse (clicks faster than the panel's rate limit) is dropped and logged (`INVALID_AUTH_PACKET`).
- Unknown packet filter state ⇒ drop (never deliver).
- Every guard and mixin fails *closed* on internal errors: a broken mod must never open the sandbox.

### Password storage

- **Argon2id** via Bouncy Castle (pure Java, bundled jar-in-jar): 64 MiB memory, 2 iterations, parallelism 2, 32-byte output, 16-byte random salt per password.
- **PBKDF2-WithHmacSHA256** fallback from the JDK (210 000 iterations, 32-byte output, 16-byte salt) when Argon2 is unavailable or explicitly configured.
- Algorithm, format version, salt, hash and the exact derivation parameters are stored per account — parameters are upgradeable without invalidating existing hashes.
- Verification is **constant-time** (`MessageDigest.isEqual`).
- Passwords, hashes and salts never appear in logs, `toString()` output or exception messages (defense-in-depth scrubber on the security log).

### Brute-force protection (four independent layers)

1. **Per-connection cooldown** — one attempt per second by default (`security.perSessionCooldownMs`).
2. **Per-IP token bucket** — 10 authentication attempts and 20 joins per IP per minute (`security.ipAuthAttemptsPerMinute`, `security.ipJoinAttemptsPerMinute`).
3. **Per-account lockout** — after 5 failed passwords the account is locked for 60 seconds (`security.maxLoginAttempts`, `security.lockoutSeconds`).
4. **Session kick** — after 10 failures within one connection the player is kicked.

Lockouts are temporary by default: a hostile third party must not be able to **permanently**
lock someone else's account by spamming wrong passwords (a denial-of-service against
arbitrary players). Permanent locking exists only as an explicit, clearly-documented
opt-in (`security.permanentLockAfterRepeatedLockouts`, dangerous) or as an administrator
action (`/auth lock`). Failed attempts, including attempts against non-existent account
names, are journaled with the source IP in `login_attempts` for auditing — and login
failures against unknown names return the same style of error as wrong passwords
(anti-enumeration).

### Session resume (quick re-login)

Session resume is a purely server-side mechanism (the AuthMe-style "session"): when a
player **disconnects while authenticated**, their identity — offline UUID, normalised
username and IP — is remembered **in memory** for `authentication.sessionPersistSeconds`
(default **43200 = 12 hours**; `0` disables). A re-join of the same UUID and username, from
the same IP when `authentication.sessionRequireSameIp` is on (default), inside that window
is auto-authenticated with no password prompt — the player skips quarantine entirely and is
logged as `SESSION_RESUMED`.

Properties and trade-offs:

- **Nothing is stored client-side** and nothing is written to the database: there is no
  bearer token that a leaked database dump or a copied client folder could replay.
- **In-memory only** — restarting the server clears every resume window. That is by design;
  a restart is a natural "log everyone out" switch.
- **Rolling, not one-shot**: a resumed session that later disconnects while authenticated
  re-records the window, so routine play chains seamlessly; the hard limit is always
  "last authenticated disconnect + window".
- **Invalidated** by `/logout` (a manual logout must never be auto-resumed), by
  `/changepassword`, by `/unregister` **and by any successful password login** (the login
  proves control of the account and resets trust: the previous window is closed).
- **The IP check is a heuristic, not an identity.** Behind shared NAT (campus, office,
  CGNAT, household) everyone shares one IP, so `sessionRequireSameIp` does not distinguish
  people behind it — anyone who can also take the same username can resume the session.
  Shorten the window (or set it to `0`) on servers where that matters, and rely on the
  security log (`SESSION_RESUMED`, actor + IP) for auditing — every resume is written
  there.

---

## Security disclaimer (read this)

> [!WARNING]
> **Everything SecureAuth does happens on the server. That is the point — and the limit.**
>
> The mod has no client component at all: no companion mod, no custom packets, no
> handshake. The chest panel is built from vanilla items by the server and rendered by the
> vanilla client as an ordinary chest; a modified client can ignore it, spam it or render
> it wrong, and none of that changes the server's state machine. SecureAuth's security
> lives **entirely in the server-side sandbox**: state machine, dimension quarantine,
> movement correction, interaction/chat/command gates, packet filtering, rate limits and
> fail-closed storage.
>
> **SecureAuth does not make offline mode equivalent to online mode.** Offline mode has no
> Mojang/Microsoft identity, no session server, no skin/cape verification, no name
> ownership beyond the server's own database. SecureAuth raises the bar for offline servers
> — it is a well-hardened lock on a door that online mode simply doesn't need — but it
> cannot reach the guarantees of `online-mode=true` with Mojang/Microsoft authentication.
>
> **If you can run your server in online mode, do that instead.** Use SecureAuth when
> online mode is genuinely impossible (isolated networks, LAN parties, offline events),
> and combine it with IP rate limiting and moderation.

---

## Requirements and installation

| Requirement | Version |
|---|---|
| Minecraft server | 26.2 |
| Fabric Loader | 0.19.5 or newer |
| Fabric API | any recent build for 26.2 (developed against 0.160.0+26.2) |
| Java | 25 (server) |
| `server.properties` | `online-mode=false` |

**Install:**

1. Set `online-mode=false` in `server.properties` (offline mode is the scenario this mod
   is built for; it does not require it, but on an online-mode server it only adds
   friction).
2. Drop the SecureAuth jar into the server's `mods/` folder.
3. Start the server once. On first run the mod generates:
   - `config/secureauth/config.yml` — fully commented default configuration,
   - `config/secureauth/secureauth.db` — SQLite account database (directory,
     file and schema are created at startup).
4. Review `config/secureauth/config.yml`, adjust, and restart (or use `/auth reload` for
   non-structural values).

Players join with **completely unmodified vanilla clients** — there is nothing to install
on the client side, and clients running other mods are unaffected because SecureAuth sends
no custom packets of any kind.

The quarantine dimension `secureauth:auth` ships as datapack JSON inside the jar
(`data/secureauth/dimension/` and `data/secureauth/dimension_type/`) — no external
datapack or world template is needed.

---

## Building from source

SecureAuth is a standard [Fabric](https://fabricmc.net/) Gradle project — the same
workflow as every open-source Fabric mod:

**Prerequisites**

- **JDK 25** (the project compiles with `--release 25`; any Temurin/Adoptium 25 build
  works). Check with `java -version`.
- Internet access for the first build — Gradle downloads Minecraft 26.2, Loom,
  Fabric API and the three bundled libraries (Bouncy Castle, SnakeYAML, SQLite JDBC)
  from Maven Central and Mojang's servers automatically.

**Build**

```console
$ git clone <this repository> secureauth
$ cd secureauth
$ ./gradlew build
```

The mod jar lands in `build/libs/secureauth-1.0.0.jar` (plus
`secureauth-1.0.0-sources.jar`). Drop the former into your server's `mods/` folder —
that's the only artifact you need. On Windows use `gradlew.bat` instead.

**What the build does**

1. `./gradlew build` resolves Loom 1.17.20 (pinned by `gradle/wrapper/`), fetches the
   unobfuscated Minecraft 26.2 server/client jars, compiles the 35 Java sources in
   `src/main/java`, expands `${version}` inside `fabric.mod.json` from
   `gradle.properties` (`mod_version=1.0.0`), and bundles the three pure-Java
   libraries as jar-in-jar dependencies (`include(...)` in `build.gradle` —
   `bcprov-jdk18on` 1.80 for Argon2id, `snakeyaml` 2.2 for the config,
   `sqlite-jdbc` 3.47.1.0 for the account database).
2. `./gradlew test` runs the JUnit 5 suite (store self-heal, config round-trip).
3. `./gradlew genSources` (optional) generates a decompiled Minecraft source jar for
   IDE browsing; `./gradlew runServer` boots a development server with the mod loaded.

**IDE import** — open the folder in IntelliJ IDEA (it detects the Gradle project
automatically) or run `./gradlew genSources` first and link it in Eclipse. The
`loom { runs { server { ... } } }` block in `build.gradle` configures the dev server run
configuration.

**Version bumps** happen in `gradle.properties` (`mod_version`); `fabric.mod.json`
picks the version up through the `processResources` expansion — never edit the version
in two places.

If the Gradle wrapper files are missing or broken in your checkout, regenerate them with a
local Gradle 9.5.1 installation (`gradle wrapper --gradle-version 9.5.1`) — the project
pins Loom 1.17.20, which requires that Gradle generation. There is no CI pipeline; verify
builds locally.

---

## Configuration reference

The full default configuration, exactly as generated at first start:

```yaml
# SecureAuth configuration
# Authentication is enforced as a server-side state transition.

authentication:
  enabled: true
  # Disconnect unauthenticated players after this many seconds.
  timeoutSeconds: 60
  # Authenticate immediately after a successful registration.
  autoLoginAfterRegister: true
  # Actionbar warning interval while waiting for authentication.
  warningIntervalSeconds: 15
  # Remember an authenticated disconnect for this many seconds; a
  # re-join from the same IP is auto-authenticated (0 = off).
  # Default: 43200 = 12 hours; a different IP always logs in normally.
  sessionPersistSeconds: 43200
  # Require the same IP for the session resume to apply.
  sessionRequireSameIp: true

password:
  # argon2id (recommended) | pbkdf2 (fallback)
  algorithm: argon2id
  minimumLength: 8
  maximumLength: 128
  argon2:
    memoryKiB: 65536
    iterations: 2
    parallelism: 2
    outputLength: 32
    saltLength: 16
  pbkdf2:
    iterations: 210000
    outputLength: 32
    saltLength: 16

security:
  maxLoginAttempts: 5
  lockoutSeconds: 60
  kickAfterFailures: 10
  perSessionCooldownMs: 1000
  ipRateLimit: true
  ipAuthAttemptsPerMinute: 10
  ipJoinAttemptsPerMinute: 20
  # WARNING: enabling this lets anyone permanently lock arbitrary
  # accounts by brute force. Leave disabled unless you accept that.
  permanentLockAfterRepeatedLockouts: false
  lockoutsForPermanentLock: 5
  lockoutCountWindowSeconds: 3600

worldProtection:
  # auth_dimension (recommended) | freeze_in_place
  isolationMode: auth_dimension
  # Holding-cell floor block. Since the cell is unbreakable bedrock:
  # an authenticated player waiting inside for the release watchdog
  # can never dig out.
  platformBlock: minecraft:bedrock
  # Interior half-extent of the cell (3 => 7x7 interior).
  platformRadius: 3
  # Enclose the platform in bedrock walls + a ceiling
  # (hollow inside — no suffocation): a stuck player can
  # only ever WAIT inside, never fall off and die.
  platformBox: true
  # Platform height inside the auth dimension: high in the
  # sky so nothing below is ever observable.
  platformY: 200
  # Automatic rescue: an authenticated player who is still
  # inside the auth dimension this many seconds after
  # login/register is teleported back to where they were
  # (re-checked every second; 0 = off).
  releaseWatchdogSeconds: 5
  # Cancel ALL damage a player takes inside the auth
  # dimension (fall, void, anything) — the sandbox is a
  # waiting room, not a hazard.
  noDamageInSandbox: true
  # Tight leash (blocks); the position is also re-synced
  # to the platform ten times per second.
  maxDriftBlocks: 1.5
  movementCorrection: true
  clearAuthEntities: true
  # Continuously remove any block that is not part of the
  # platform (water, lava, legacy leftovers, accidents).
  pureVoid: true
  # Quarantined players get infinite blindness (thick fog).
  quarantineBlindness: true
  # Regenerate the void on every server restart with a
  # fresh random seed (never the overworld seed).
  resetOnRestart: true
  blockInteraction: true
  blockChat: true
  blockCommands: true

worldInfo:
  # Minimise information leaked to unauthenticated clients.
  hideTabList: true
  suppressChatBroadcasts: true
  hideMaps: true
  minimalCommandTree: true
  filterScoreboard: false
  filterCustomPayloads: false

ui:
  # Show the countdown + login hint on the action bar (above the
  # hotbar) instead of repeating warnings in chat.
  actionBarTimer: true
  # Open the chest-style auth panel (vanilla clients see a chest menu).
  autoOpenAuthPanel: true
  # Enable the admin chest panel via /auth panel.
  adminPanel: true

storage:
  databasePath: config/secureauth/secureauth.db

identity:
  # Bind accounts to the offline UUID captured at registration.
  strictUuidBinding: false

administration:
  adminOpLevel: 2

logging:
  authenticationEvents: true
  logToFile: true
  logDir: logs/secureauth
  maxFileBytes: 5242880
  maxFiles: 5
  logToDatabase: true
```

Notable options:

| Option | Effect | Notes |
|---|---|---|
| `authentication.enabled` | Master switch; `false` makes the mod completely inert | Restart required |
| `authentication.timeoutSeconds` | Idle limit before an unauthenticated player is kicked | Clamped to ≥ 5 |
| `authentication.sessionPersistSeconds` | Server-side session resume window (same-IP quick re-login) | 0 disables it; short windows recommended |
| `authentication.sessionRequireSameIp` | Bind the resume record to the disconnect IP | Off is riskier behind NAT anyway — see [session resume](#session-resume-quick-re-login) |
| `password.algorithm` | `argon2id` or `pbkdf2` | Applies to **new** hashes; existing hashes verify with their stored parameters |
| `password.minimumLength` / `maximumLength` | Length-only policy (composition rules hurt more than they help) | Reload applies to new registrations |
| `security.maxLoginAttempts` + `lockoutSeconds` | Temporary account lockout | Clamped: `kickAfterFailures ≥ maxLoginAttempts` |
| `security.ipRateLimit` + `ipAuth/ipJoinAttemptsPerMinute` | Per-IP token buckets | Capacity fixed at startup; restart to change |
| `security.permanentLockAfterRepeatedLockouts` | **Dangerous** — anyone can permanently lock any account by brute force | Off by default, deliberately |
| `worldProtection.isolationMode` | `auth_dimension` (recommended) or `freeze_in_place` | `freeze_in_place` keeps the player where they joined, immobilised |
| `worldProtection.platformBlock` / `platformBox` / `platformRadius` | Holding-cell floor material, box shape and interior size | Bedrock + box by default — unbreakable, no falling out |
| `worldProtection.platformY` | Cell height inside the void | Default 200, clamped 1–250 (dimension spans 0–255) |
| `worldProtection.releaseWatchdogSeconds` | Auto-rescue window for authenticated players still stuck inside | 0 disables; clamped 0–60 |
| `worldProtection.noDamageInSandbox` | Cancel all damage inside the auth dimension | On by default |
| `worldProtection.quarantineBlindness` | Infinite blindness while quarantined | On by default |
| `worldProtection.resetOnRestart` | Wipe + re-seed the dimension every boot | On by default |
| `worldProtection.maxDriftBlocks` | Teleport-back radius around the cell | `movementCorrection` must be on |
| `worldInfo.minimalCommandTree` | Send only the auth command literals to unauthenticated clients | Hides plugin/mod command surface |
| `ui.actionBarTimer` | Countdown + hint on the action bar instead of chat spam | On by default |
| `ui.autoOpenAuthPanel` | Open the player chest panel on join and on every re-prompt | See [chest auth panel](#chest-auth-panel-vanilla-clients) |
| `ui.adminPanel` | Enable the `/auth panel` admin chest GUI | Admin permission still required |
| `administration.adminOpLevel` | Vanilla permission level for `/auth` | 1–4, default 2 |
| `logging.*` | Security log to rotating files and/or the database | 5 MiB × 5 files by default |
| `storage.databasePath` | SQLite file location | Restart required |

`/auth reload` re-reads the file and copies every field into the live configuration, so
runtime checks (timeouts, block gates, visibility flags, session-resume window, panel
toggles, admin level, logging) pick changes up immediately. Structural values — the
database path, IP rate limiter capacities, and the hash parameters of already-stored
passwords — only apply to new accounts or after a restart; the reload reply says so.

---

## Commands and permissions

Player commands (available to everyone):

| Command | Description | Valid from |
|---|---|---|
| `/register <password> <confirm>` | Create an account for your name, then (by default) log in immediately | `UNREGISTERED` / `REGISTERING` |
| `/login <password>` | Authenticate this connection | any unauthenticated state |
| `/logout` | End your session: back into the sandbox, prompt again, resume window invalidated | `AUTHENTICATED` |
| `/authpanel` | Re-open your chest auth panel (see [chest auth panel](#chest-auth-panel-vanilla-clients)) | any state with a live session |
| `/changepassword <oldPassword> <newPassword> <confirm>` | Change your own password (also drops any resume window) | `AUTHENTICATED` |
| `/unregister <password>` | Delete your own account and return to the register prompt | `AUTHENTICATED` |

Administration (`/auth`, requires vanilla permission level `administration.adminOpLevel`,
default 2; console always qualifies). Bare `/auth` prints
`Usage: /auth <info|reset|unregister|lock|unlock|forcelogout|panel|list|reload> [player]`:

| Command | Description |
|---|---|
| `/auth info <player>` | Account metadata: registration date, last login, lock state, lockout end, failed attempts, hash algorithm — never salt, hash or parameters |
| `/auth reset <player> <newPassword>` | Force-set a new password (policy-checked), clear failures and lockout; the target must log in with the new password. Logs `ADMIN_RESET` |
| `/auth unregister <player>` | Delete the account; an online target is sent back to the sandbox and re-prompted first. Logs `ADMIN_UNREGISTER` |
| `/auth lock <player>` | Permanent lock (login refused until unlocked). Logs `ACCOUNT_PERMANENTLY_LOCKED` |
| `/auth unlock <player>` | Lift a lock and clear the lockout; an online locked target is re-prompted. Logs `ACCOUNT_UNLOCKED` |
| `/auth forcelogout <player>` | Send an online, authenticated player back to the sandbox (their resume window is invalidated too). Logs `ADMIN_FORCE_LOGOUT` |
| `/auth panel` | Open the admin chest GUI over the live session table (see [chest auth panel](#chest-auth-panel-vanilla-clients)) |
| `/auth list [page]` | Paginated account list (10 per page) with last-login times |
| `/auth reload` | Re-read `config/secureauth/config.yml` into the live configuration; logs `CONFIG_ERROR` on failure |

Case-insensitivity: account lookups use the normalized (lowercase) name, so `/auth info
Steve` and `/auth info steve` are equivalent.

> [!NOTE]
> **Passwords are typed in chat, so they appear in the *client's own* chat history.**
> The server never echoes, stores or logs them, and other players never see them, but the
> local Minecraft client keeps what you typed in its chat history like any command
> (client-side `options.txt` history). That is inherent to chat-command authentication on
> a vanilla client — there is no GUI text field a server-only mod can show. Players who
> care (streaming, shared machines) should use a unique password they do not reuse
> elsewhere, and can clear their client's chat history afterwards.

> [!NOTE]
> **The pre-auth command gate covers `/authpanel` too.** The gate's allow-list is the six
> command roots `register`, `login`, `logout`, `changepassword`, `unregister`, `auth`, so
> typing `/authpanel` *before* logging in is currently blocked with the generic
> "commands are unavailable" notice — a known limitation. The panel auto-opens on join and
> re-opens whenever the server re-prompts, and its guidance (the exact `/login` /
> `/register` syntax) lives in the item lore, so the command is not needed pre-auth. See
> [chest auth panel](#chest-auth-panel-vanilla-clients).

The permission model is deliberately simple: there are no per-command permission nodes —
the vanilla op level from `administration.adminOpLevel` gates all of `/auth`. Player
commands need no permission; they are the only commands unauthenticated players can run.

### Localization

All player-facing text is translatable keys resolved through vanilla lang files under
`assets/secureauth/lang/`. The mod ships four complete catalogs with full key parity:
`en_us.json` (the reference), `zh_cn.json` (Simplified Chinese), `ja_jp.json` (Japanese)
and `ru_ru.json` (Russian); clients render whichever their language setting selects, and
any key missing from a translation falls back to English. To add another language, copy
`en_us.json` to `<code>.json`, translate the values and keep the `%s` placeholders and
`§` color codes intact — no code changes needed.

---

## Chest auth panel (vanilla clients)

SecureAuth's GUI is the "economy shop plugin" pattern: **menus the server builds out of
vanilla chest slots**, opened through the ordinary vanilla container-menu protocol. An
unmodified client renders them as perfectly ordinary chests — no client mod, no custom
payload, no resource pack. Three classes in `net.secureauth.ui` implement it.

### `ChestGui` — the base class

`ChestGui` extends the vanilla `ChestMenu` and enforces the rules that make a server-built
menu safe:

- **Vanilla menu types only**: panels use `MenuType.GENERIC_9x3` (27 slots) and
  `MenuType.GENERIC_9x6` (54 slots). A vanilla client must be able to open them natively —
  this is the whole compatibility contract.
- **Clicks are intercepted, never forwarded**: `clicked()` is final and deliberately never
  calls `super.clicked`, so the virtual button items can never be picked up, moved, cloned
  or smuggled into a player inventory. `quickMoveStack` returns `EMPTY` (shift-clicks are
  swallowed too). The vanilla click protocol self-corrects the client's optimistic
  prediction, so a swallowed click simply snaps back on the player's screen.
- **Viewer-bound**: `stillValid` is true only for the player the menu was built for (and
  only while they are not removed) — nobody else can keep the menu open or act in it.
- **Click-spam guard**: at most one click per 100 ms is processed; faster clicking triggers
  the subclass's `onClickSpam()` hook at most once per 5-second window, which logs
  `INVALID_AUTH_PACKET` with details like `panel_click_spam`.
- **Live refresh**: `refresh()` clears the grid, rebuilds every item from the current
  server state and syncs the client, so an open panel tracks the session in real time.

### `AuthPanel` — the player panel

A 27-slot panel (`GENERIC_9x3`) that replaces the old client-side auth screen. Layout:

```
[ filler ×4 ] [ player head: account status ] [ filler ×4 ]
[ filler ×2 ] [ book: log in ] [ barrier: locked ] [ writable book: register ] [ filler ×3 ]
[ filler ×4 ] [ clock: time left ] [ filler ×3 ]
```

- **Head** (slot 4): the viewer's own head with state (authenticated / awaiting
  authentication / not registered / temporarily locked / admin-locked) and attempts
  remaining before lockout.
- **"Log in" book** (slot 11) and **"Create account" writable book** (slot 15), both
  enchanted-glinted: the guidance *is* the lore — the exact command to type. (The click
  handler echoes the same hint line to chat, but while unauthenticated the pre-auth
  container-click guard swallows container clicks before they reach the menu, so the lore
  is what actually guides the player — the panel never *needs* a click to work.)
- **Locked barrier** (slot 13): shown in lockout state, with the remaining seconds (or the
  "contact an administrator" text for permanent locks).
- **Deadline clock** (slot 22): seconds until the timeout disconnect.
- On successful authentication the panel closes itself. Re-opening it later (e.g.
  `/authpanel` while authenticated) shows a green "Authenticated" star instead of the
  action items.

**Passwords are never typed into a chest grid.** A grid cannot hold a secret: items are
visible, and the pre-auth container-click guard blocks grid interaction anyway (see the
sandbox table above). The panel is the *status and guidance* surface; the credential
channel is the chat command, and the panel tells the player exactly which one to type.

Lifecycle: auto-opens on join (`ui.autoOpenAuthPanel`, default on) and whenever the server
(re-)sends the auth prompt (respawn, logout, unregister, unlock transitions); refreshes
itself live on every state change while it is open (wrong password → attempts drop,
lockout → barrier and countdown appear); closes on successful authentication.
`/authpanel` re-opens it on demand. Every open is logged as `PANEL_OPENED`.

### `AdminPanel` — the admin GUI

`/auth panel` (admin permission, `ui.adminPanel` toggle, in-game viewer required — the
console gets a hint to use the chat subcommands instead) opens a 54-slot panel
(`GENERIC_9x6`):

- **Summary item**: online players, authenticated count, awaiting-authentication count.
- **Online player heads** (45 per page): each head's lore shows the live state, attempts
  remaining and join IP. Arrow/paper items below paginate.
- **Detail page** (click a head; 27 slots): the target's head with state, attempts, IP and
  hash algorithm, plus actions — **Lock account** (barrier), **Unlock account** (emerald),
  **Force logout** (redstone), **Reset password** (paper — prints the `/auth reset`
  syntax into chat, because a secret can never be typed into a chest grid), and **Back**.

Every panel action routes through the exact same `AuthManager` / repository code paths as
its chat-command twin and lands in the security log with the same event
(`ACCOUNT_PERMANENTLY_LOCKED`, `ACCOUNT_UNLOCKED`, `ADMIN_FORCE_LOGOUT`, …) and a
`details="panel"` marker, so auditing never has to care whether an admin clicked or typed.
The panel refreshes after every action.

---

## Architecture overview

### Package layout (`src/main/java` — the only source set)

```
net.secureauth
├── SecureAuth                  mod entrypoint: config load, service wiring, Fabric event
│                               receivers (no networking: no custom packets exist)
├── auth
│   ├── AuthManager             orchestrator: sessions, prompts, all user feedback,
│   │                           release watchdog + ability reconciliation ticks
│   ├── AuthSession             per-connection state (player, state, snapshot, deadline,
│   │                           open panel reference)
│   ├── AuthState               UNREGISTERED / REGISTERING / REGISTERED_NOT_AUTHENTICATED
│   │                           / AUTHENTICATED / LOCKED
│   ├── RegistrationService     register flow: policy, uniqueness, hash, journal
│   ├── LoginService            login flow: cooldown → IP limit → lockout → verify → kick
│   ├── PasswordPolicy          length-only password policy
│   ├── PasswordService         Argon2id (BouncyCastle) + PBKDF2 fallback, constant-time
│   └── SessionResumeService    in-memory same-IP quick re-login (AuthMe-style session)
├── account
│   ├── AccountDatabase         SQLite open/migrate/transactional (WAL), self-healing
│   ├── AccountRepository       accounts + login_attempts data access (normalize, lockout)
│   ├── Account                 identity + password material + bookkeeping
│   └── StoreException          root-cause diagnostics for store failures
├── security
│   ├── SecurityEvent           22 typed event constants (no payload types)
│   ├── SecurityLogger          rotating file sink + database sink, redacted
│   ├── Redactor                regex scrubber as defense in depth
│   ├── RateLimiter             token bucket (IP join/auth limits)
│   └── LoginAttemptTracker     per-connection cooldown + failure counter
├── world
│   ├── AuthWorldManager        quarantine/restore, holding cell, drift + escape
│   │                           correction, rescue, ability reconciliation, purifier
│   └── OriginalLocation        pre-quarantine snapshot (dimension/pos/rotation/mode)
├── network
│   ├── PacketFilterService     outgoing info isolation + tab list/command tree control
│   └── PacketBypass            thread-local bypass so SecureAuth's own chat and
│                               tab-list packets pass the filter
├── ui
│   ├── ChestGui                chest-menu base class (click interception, viewer binding)
│   ├── AuthPanel               27-slot player auth panel (auto-open, live refresh)
│   └── AdminPanel              54-slot admin GUI + per-player detail page (/auth panel)
├── command
│   └── AuthCommands            /register /login /logout /authpanel /changepassword
│                               /unregister /auth <info|reset|unregister|lock|unlock|
│                               forcelogout|panel|list|reload>
├── lang
│   └── Lang                    server-side message resolver (en/zh/ja/ru catalogs)
├── mixin
│   ├── ServerCommonPacketListenerImplMixin   outgoing packet filter
│   ├── CommandsMixin                          pre-auth command gate
│   ├── ServerGamePacketListenerImplMixin     movement + action + container gates
│   ├── ItemEntityMixin                        item pickup gate
│   ├── ServerLevelMixin                       entity birth guard for the auth dimension
│   ├── MinecraftServerMixin                   per-boot re-seed of the auth dimension
│   └── EntityMixin                            stale-removal-flag clear (teleport repair)
└── config
    └── AuthConfig              typed YAML config, clamped, self-writing defaults
```

There is no client source set. `fabric.mod.json` declares `"environment": "server"` and a
single `main` entrypoint; `secureauth.mixins.json` contains the seven server mixins.
Everything the mod sends is a vanilla packet (chat components, container menu opens and
content syncs), which is why unmodified clients are fully compatible.

### Database schema (SQLite, `config/secureauth/secureauth.db`)

```sql
-- accounts: one row per registered name
CREATE TABLE accounts (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    username_norm    TEXT NOT NULL UNIQUE,      -- canonical lowercase key
    username_display TEXT NOT NULL,             -- casing as first registered
    uuid_offline     TEXT,                      -- offline UUID at registration
    algorithm        TEXT NOT NULL,             -- 'argon2id' | 'pbkdf2'
    hash_version     INTEGER NOT NULL,          -- format version
    salt             BLOB NOT NULL,
    hash             BLOB NOT NULL,
    hash_params      TEXT NOT NULL,             -- derivation parameters, versioned
    created_at       INTEGER NOT NULL,
    last_login       INTEGER,
    failed_attempts  INTEGER NOT NULL DEFAULT 0,
    lockout_until    INTEGER NOT NULL DEFAULT 0,
    locked           INTEGER NOT NULL DEFAULT 0 -- permanent (admin) lock
);

-- login_attempts: audit journal (IP retained for abuse protection)
CREATE TABLE login_attempts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER,
    username   TEXT,
    ip         TEXT,
    success    INTEGER NOT NULL,
    reason     TEXT,                            -- 'login' | 'register' | 'wrong_password' | ...
    timestamp  INTEGER NOT NULL
);

-- security_events: structured audit log (database sink)
CREATE TABLE security_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,                   -- SecurityEvent name
    actor      TEXT,
    target     TEXT,
    ip         TEXT,
    details    TEXT,
    timestamp  INTEGER NOT NULL
);

-- schema_migrations: versioning for in-place upgrades
CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL);
```

No sessions table exists: session resume is in-memory by design.

All writes run inside transactions (with the close/reopen/retry-once self-heal on
failure); the database runs with WAL journaling, `synchronous=NORMAL`, foreign keys on,
and a 5-second busy timeout, plus a 30-second health probe.

### Security events (22)

Every entry records event type, actor, target, IP and scrubbed details:

| Event | Meaning |
|---|---|
| `ACCOUNT_REGISTERED` | A player registered a new account |
| `LOGIN_SUCCESS` | A player authenticated successfully |
| `LOGIN_FAILURE` | A login attempt failed |
| `ACCOUNT_LOCKED` | An account entered a temporary lockout |
| `ACCOUNT_UNLOCKED` | An account lockout was lifted |
| `ACCOUNT_PERMANENTLY_LOCKED` | An account was permanently locked |
| `PASSWORD_CHANGED` | A password was changed |
| `ADMIN_RESET` | An administrator reset an account |
| `ADMIN_UNREGISTER` | An administrator deleted an account |
| `ADMIN_FORCE_LOGOUT` | An administrator forced a player back to the auth area |
| `SESSION_RESUMED` | A returning player was auto-authenticated by the IP-bound session resume |
| `AUTH_TIMEOUT` | A player was disconnected for not authenticating in time |
| `PLAYER_QUARANTINED` | A player entered the pre-authentication sandbox |
| `AUTH_STATE_RESTORED` | A player was restored to the real world |
| `REGISTRATION_REJECTED` | A registration attempt was rejected |
| `COMMAND_BLOCKED` | A command was blocked before authentication |
| `SANDBOX_ESCAPE_CORRECTED` | Unauthorised movement was corrected — also carries watchdog rescues (`release_watchdog_rescued`), ability repairs (`restricted_outside_sandbox`) and void purifier reports |
| `INVALID_AUTH_PACKET` | An invalid or abusive panel interaction arrived |
| `PANEL_OPENED` | A chest panel was opened |
| `DATABASE_UNAVAILABLE` | The account database failed (with its root cause) |
| `CONFIG_ERROR` | A configuration problem was detected |
| `SERVER_STOPPED` | The server stopped; all sessions invalidated |

### Privacy

- **Passwords, hashes and salts are never written to any log or event** — not by design
  and not by accident (the logger redacts credential-shaped values as defense in depth,
  and no code path hands secrets to it).
- The security log (`logs/secureauth/*.log`, rotated 5 MiB × 5, and the
  `security_events` table) records event type, actor, target, **IP** and scrubbed details.
  IP addresses in `login_attempts` and `security_events` exist for brute-force and
  abuse-response — that is their only purpose; delete rows or drop the sinks
  (`logging.logToDatabase`, `logging.logToFile`, `logging.authenticationEvents`) to remove
  them. A dedicated privacy mode that stops storing IPs entirely is a deliberate
  non-goal: without IPs the rate limiter's audit trail is useless.
- Session resume stores only UUID, normalised name, IP and an expiry timestamp, in
  memory, never on disk.
- No telemetry of any kind.

---

## Verification checklist

Manually verify a deployment against this list (all defaults; adjust names where noted):

1. Fresh player joins → lands inside the bedrock holding cell in the `secureauth:auth`
   void (blindness fog active, adventure mode on), register prompt arrives in chat
   **and the chest panel auto-opens** (head shows "Not registered", register book shows
   the `/register` syntax in its lore).
2. `/register secret123 secret123` → account created, auto-login, restored to the exact
   pre-join dimension/position/rotation and game mode; the panel closes itself; the tab
   list repopulates immediately (no rejoin needed).
3. `/register short short` → rejected with the minimum-length error; an open panel
   refreshes its items.
4. Register with a mismatched confirmation → "Passwords do not match."
5. Rejoin → login prompt (chat + panel); wrong password → "Incorrect password." and the
   panel head's attempts-left line drops (the panel refreshes live; its items never move).
6. Five wrong passwords → temporary lockout message with seconds; the panel shows the
   barrier with a live countdown; further attempts refuse until the lockout lapses.
7. Ten failures in one connection → kicked outright.
8. Hammering `/login` from one IP (many accounts or reconnects) → rate-limit message.
9. Idle for 60 s → countdown warnings, then timeout disconnect (`AUTH_TIMEOUT` logged).
10. While unauthenticated: sprint/strafe visually but the server snaps position back
    (check `SANDBOX_ESCAPE_CORRECTED` in the security log); with
    `isolationMode: freeze_in_place` the player cannot move at all.
11. Break/place a block, open a chest, use an item, attack a mob → all cancelled with a
    throttled notice.
12. Drop an item / press Q / swap hands → blocked.
13. Walk an item into yourself → no pickup (entity stays on the ground).
14. Send chat → blocked message; other players don't receive it.
15. Run `/gamemode creative` or any non-auth command → blocked; only the
    `register/login/logout/changepassword/unregister/auth` roots pass the gate.
16. Tab completion while unauthenticated → only the auth literals are suggested
    (minimal command tree: `register`, `login`, `auth`).
17. Tab list while unauthenticated → no other players (have a second account online).
18. Another player joins/leaves/chats/gets an advancement while you are unauthenticated →
    you see none of it.
19. Maps: with a second account holding a filled map, the unauthenticated viewer never
    receives map data packets.
20. Kill/rejoin in a way that respawns you unauthenticated → re-quarantined, re-prompted
    and the panel re-opened (respawn guard).
21. `/logout` while authenticated → back in the sandbox, login prompt, panel re-opened,
    and the resume window is gone: rejoining within the window requires the password.
22. Session resume: log in, disconnect, rejoin from the same IP within 12 hours →
    auto-authenticated, no quarantine (`SESSION_RESUMED` logged, "Session resumed —
    welcome back"); restarting the server clears the window; `/logout` before
    disconnecting also clears it.
23. `/changepassword oldPa55 newPa55 newPa55` → old password required, new one enforced on
    next login; wrong old password → error, nothing changes.
24. `/unregister secret123` → account gone, register prompt back.
25. `/auth info <player>` as an op → metadata only; as a non-op → permission denied;
    `/auth reset` enforces the password policy; `/auth lock`/`unlock` round-trips;
    `/auth forcelogout` re-sandboxed an online player; `/auth list 2` paginates;
    `/auth reload` applies an edited `timeoutSeconds` immediately.
26. `/auth panel` as an op → summary item with live counts, online heads with state lore,
    pagination, detail page: Lock/Unlock round-trips the target's state, Force logout
    re-sandboxes them, Reset password prints the command hint in chat, Back returns;
    the security log shows the same events as the chat commands with `details=panel`.
    As a non-op → permission denied; from the console → "needs an in-game viewer".
27. Spam-click the admin panel → items never move; at most one
    `INVALID_AUTH_PACKET` (`admin_panel_click_spam`) entry per 5-second window.
28. **Watchdog**: authenticate while the server is lagging (or simulate a failed release)
    → within ~5 seconds the "you were stuck" notice arrives and the player is back at
    their snapshot (`release_watchdog_rescued` in the security log).
29. **Ability auto-restore**: as an operator, `/tp` an unauthenticated player out of the
    sandbox, then have them `/login` → within a second the game type, blindness and
    flags are fully repaired even if the login-time restore missed the live entity
    (`restricted_outside_sandbox; abilities_restored` in the security log) — and a later
    `/gamemode` by an operator on that player is *not* fought.
30. Break the database (rename `secureauth.db` mid-run or revoke permissions) → joins
    still quarantine, logins fail closed with "temporarily unavailable", nothing opens
    up; restore it → the store self-heals within ~30 s.
31. Inspect `logs/secureauth/*.log` and `security_events` after all of the above → events
    present, zero passwords/hashes anywhere.

---

## Troubleshooting and FAQ

**Players fall into the void / the auth dimension is missing.**
The `secureauth:auth` dimension data ships inside the jar. If you removed datapacks or a
world import stripped it, SecureAuth falls back to `freeze_in_place` isolation (fail
closed — check the log for `PLAYER_QUARANTINED … mode=freeze_in_place`). Restore the jar's
`data/secureauth/` folder into the world's datapacks (or just keep the mod jar present) and
restart. Also verify `worldProtection.platformY` (200) sits below the dimension's height
limit (256).

**Junk blocks / entities / water appear in the auth dimension.**
With the shipped generator this is impossible — the dimension is flat air with a custom
no-spawner biome, non-player entities are refused at birth by a mixin and a purifier
removes any block that is not part of the holding cell once per second. Leftovers can
only be legacy saved chunks (wiped automatically on every restart — check for "auth
dimension reset" in the log) or an *external* datapack overriding the mod's dimension
JSON: run `/datapack list` and disable anything that also defines `secureauth:auth`.

**A player is stuck outside the sandbox without block interaction ("logged in but can't
break blocks").**
They should not be — the ability reconciliation repairs exactly that within a second
(`restricted_outside_sandbox; abilities_restored` in the security log). If you still see
it, check the game type manually (`/data get entity <player> playerGameType`) — an
operator may have legitimately set the player to adventure; the reconciliation never
fights operator changes after the first check.

**A player closed their panel — how do they get it back?**
The panel re-opens automatically whenever the server (re-)sends the auth prompt: on join,
on respawn, and on logout/unregister/lock transitions. `/authpanel` re-opens it on demand,
but note the pre-auth command gate also covers `/authpanel` (see the note in
[commands](#commands-and-permissions)) — while unauthenticated, the reliable paths are the
item-lore hints and the chat prompt. This is a known rough edge; the practical workaround
is fine because the panel is guidance, not a requirement: `/login` works from chat alone.

**Can players type their password into the chest panel?**
No, by design. A chest grid cannot hold a secret — items are visible to everyone with the
menu open, and the pre-auth container-click guard blocks grid interaction anyway. The
panel's action items only carry and print the `/login` and `/register` syntax; the
credential channel is the chat command.

**Session resume: why does my friend get auto-logged-in as me?**
They are joining from the same IP (shared household/campus/CGNAT NAT) with your username
inside your resume window. The window is bound to UUID + name + (by default) IP, not to a
person. Keep `sessionPersistSeconds` small (or 0), keep `sessionRequireSameIp: true`, and
remember `/logout` invalidates the window immediately.

**Log line says "Argon2 unavailable" / logins fail after swapping libraries.**
The mod falls back to PBKDF2 for *new* accounts when Bouncy Castle cannot be loaded.
Existing Argon2 hashes cannot be verified without Argon2 — that is fail-closed by design.
Keep the bundled jar-in-jar intact; don't strip BC from the jar.

**"SQLite locked" / "database is busy" errors.**
The database is opened in WAL mode with a 5 s busy timeout and is designed for exactly one
server per file. Don't point two servers at the same `secureauth.db`, and don't copy it
while the server is running — stop the server, then back up. The single writer is the
server thread; if you see lock errors, something external is holding a transaction
(backup tools, sqlite3 CLI sessions). The store self-heals (close/reopen/retry) and every
failure is journaled with its root cause under `DATABASE_UNAVAILABLE`.

**Migrating from another auth plugin (AuthMe, LoginSecurity, …).**
Not supported: hash formats, salts and parameters differ, and importing verifiable hashes
would require re-implementing every legacy format. Have players re-register once, then
delete the old plugin's data. `/auth reset <player> <newPassword>` gives admins a way to
pre-provision accounts if they accept handing out the initial password.

**Can I use SecureAuth on an online-mode server?**
You can (`authentication.enabled` doesn't check `online-mode`), but it adds friction
without adding security — Mojang/Microsoft already authenticate everyone. Prefer leaving
it off; if you run it, you own the password-reset workload.

**`/auth reload` changed the rate limit / database path, but nothing happened.**
Structural values (database path, IP token-bucket capacities, hash parameters of stored
accounts) are captured at startup. Restart the server to apply them — the reload reply
warns about this.

**Where do I see who tried to brute-force my server?**
`logs/secureauth/` (rotating text log) and the `security_events`/`login_attempts` tables
(see the schema above). Filter `LOGIN_FAILURE` by `ip`, and cross-reference the timestamp
with your server's own logs for proxy/VPN context.

---

## License

MIT — see [LICENSE](LICENSE). SecureAuth is provided "as is"; you are responsible for
your server's security posture, backups and abuse response.
