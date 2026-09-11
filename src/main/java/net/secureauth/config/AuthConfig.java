package net.secureauth.config;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;

/**
 * Human-readable YAML configuration for SecureAuth.
 *
 * <p>All major behaviours are configurable; the file is loaded at server start
 * and can be re-read at runtime with {@code /auth reload}. Structural options
 * (database path, hash parameters of existing accounts) always take effect for
 * new accounts or after a restart.</p>
 */
public final class AuthConfig {

        public final AuthenticationSection authentication = new AuthenticationSection();
        public final PasswordSection password = new PasswordSection();
        public final SecuritySection security = new SecuritySection();
        public final WorldProtectionSection worldProtection = new WorldProtectionSection();
        public final WorldInfoSection worldInfo = new WorldInfoSection();
        public final UiSection ui = new UiSection();
        public final StorageSection storage = new StorageSection();
        public final IdentitySection identity = new IdentitySection();
        public final AdministrationSection administration = new AdministrationSection();
        public final LoggingSection logging = new LoggingSection();

        public static final class AuthenticationSection {
                /** Master switch: when false the mod performs no enforcement at all. */
                public boolean enabled = true;
                /** Seconds before an unauthenticated connection is disconnected. */
                public int timeoutSeconds = 60;
                /** Authenticate automatically right after a successful registration. */
                public boolean autoLoginAfterRegister = true;
                /** Warn the player every N seconds while waiting for authentication. */
                public int warningIntervalSeconds = 15;
                /** Seconds an authenticated disconnect is remembered for quick re-login (0 = off, default 12 h). */
                public int sessionPersistSeconds = 43200;
                /** Require the same IP for the session resume to apply. */
                public boolean sessionRequireSameIp = true;
        }

        public static final class PasswordSection {
                /** "argon2id" (recommended) or "pbkdf2" (JDK fallback). */
                public String algorithm = "argon2id";
                public int minimumLength = 8;
                public int maximumLength = 128;
                public final Argon2Params argon2 = new Argon2Params();
                public final Pbkdf2Params pbkdf2 = new Pbkdf2Params();

                public static final class Argon2Params {
                        public int memoryKiB = 65_536; // 64 MiB
                        public int iterations = 2;
                        public int parallelism = 2;
                        public int outputLength = 32;  // bytes
                        public int saltLength = 16;     // bytes
                }

                public static final class Pbkdf2Params {
                        public int iterations = 210_000;
                        public int outputLength = 32;
                        public int saltLength = 16;
                }
        }

        public static final class SecuritySection {
                /** Failed logins before the account is temporarily locked. */
                public int maxLoginAttempts = 5;
                /** Temporary lockout duration in seconds. */
                public int lockoutSeconds = 60;
                /** Session failures before the player is kicked outright. */
                public int kickAfterFailures = 10;
                /** Cooldown between two login attempts from the same connection. */
                public long perSessionCooldownMs = 1_000L;
                /** IP-based rate limiting of join and authentication attempts. */
                public boolean ipRateLimit = true;
                /** Authentication attempts per IP per minute. */
                public int ipAuthAttemptsPerMinute = 10;
                /** Joins per IP per minute (protects against reconnect spam). */
                public int ipJoinAttemptsPerMinute = 20;
                /** Permanently lock accounts after lockouts (DANGEROUS: enables denial of service against arbitrary accounts). */
                public boolean permanentLockAfterRepeatedLockouts = false;
                /** Number of lockouts within the window that trigger a permanent lock (if enabled). */
                public int lockoutsForPermanentLock = 5;
                /** Window in seconds considered when counting lockouts. */
                public long lockoutCountWindowSeconds = 3_600L;
        }

        public static final class WorldProtectionSection {
                /** "auth_dimension" (recommended) or "freeze_in_place". */
                public String isolationMode = "auth_dimension";
                /**
                 * Block used for the holding-cell floor (since 1.2.4: bedrock by
                 * default — the cell must be unbreakable even by an authenticated
                 * player who gets stuck in it while waiting for the release
                 * watchdog).
                 */
                public String platformBlock = "minecraft:bedrock";
                /**
                 * Interior half-extent of the holding cell: 3 => 7x7 interior.
                 * The enclosing shell (walls + ceiling) is always bedrock and
                 * sits one block further out.
                 */
                public int platformRadius = 3;
                /**
                 * Enclose the holding platform in unbreakable bedrock walls and
                 * a ceiling (since 1.2.4): a player inside can never fall off,
                 * fall out or suffocate — the worst case of a failed release is
                 * "waiting inside a sealed cell", never "dying in the void".
                 */
                public boolean platformBox = true;
                /**
                 * Release watchdog (since 1.2.4, 5 s default): any AUTHENTICATED
                 * player who is still physically inside the auth dimension this
                 * many seconds after login/register is automatically teleported
                 * back to their original location (re-checked every second —
                 * lag-failed dimension transfers cannot strand anyone). 0 = off.
                 */
                public int releaseWatchdogSeconds = 5;
                /**
                 * Cancel every point of damage a player takes inside the auth
                 * dimension (since 1.2.4): fall damage from a mid-air rejoin,
                 * void damage, anything — the sandbox is a waiting room, not a
                 * hazard. Quarantined players are additionally invulnerable.
                 */
                public boolean noDamageInSandbox = true;
                /**
                 * Platform Y level inside the auth dimension (since 1.2.2: 200). The
                 * platform sits high in the sky, far above anything a quarantined
                 * client could observe below it, and the sandbox blindness keeps the
                 * horizon close anyway.
                 */
                public int platformY = 200;
                /**
                 * Teleport the player back to the platform if it drifts further than
                 * this (since 1.2.2: 1.5 — a tight leash; the server also re-syncs the
                 * authoritative position ten times per second).
                 */
                public double maxDriftBlocks = 1.5;
                /** Continuously correct unauthorised movement server-side. */
                public boolean movementCorrection = true;
                /** Clear stray entities inside the auth dimension (spawn-blocking + sweep). */
                public boolean clearAuthEntities = true;
                /** Keep the auth dimension a pure void: remove any block that is not part of the platform. */
                public boolean pureVoid = true;
                /**
                 * Apply infinite blindness while a player is quarantined (since 1.2.2).
                 * The thick fog keeps anything the client could still render of the
                 * sandbox out of view; it is removed on restore.
                 */
                public boolean quarantineBlindness = true;
                /**
                 * Regenerate the auth dimension from scratch on every server restart
                 * (since 1.2.2): all saved chunk files are wiped at stop/start, the
                 * seed is re-randomised per boot, and the dimension never accumulates
                 * saved state.
                 */
                public boolean resetOnRestart = true;
                public boolean blockInteraction = true;
                public boolean blockChat = true;
                public boolean blockCommands = true;
        }

        public static final class WorldInfoSection {
                /** Hide other players from the tab list of unauthenticated viewers. */
                public boolean hideTabList = true;
                /** Suppress chat/JOIN/LEAVE/ADVANCEMENT broadcasts to unauthenticated viewers. */
                public boolean suppressChatBroadcasts = true;
                /** Suppress map data packets to unauthenticated viewers. */
                public boolean hideMaps = true;
                /** Replace the full command tree with a minimal auth-only tree. */
                public boolean minimalCommandTree = true;
                /** Filter scoreboard packets (requires scoreboard resync on auth). */
                public boolean filterScoreboard = false;
                /** Filter other mods' custom payloads (may break other mods). */
                public boolean filterCustomPayloads = false;
        }

        public static final class UiSection {
                /** Show the authentication countdown + hint on the action bar instead of periodic chat warnings. */
                public boolean actionBarTimer = true;
                /** Open the chest-style auth panel automatically when an unauthenticated player joins. */
                public boolean autoOpenAuthPanel = true;
                /** Enable the admin chest panel (/auth panel). */
                public boolean adminPanel = true;
        }

        public static final class StorageSection {
                /** Path of the SQLite database, relative to the server working directory. */
                public String databasePath = "config/secureauth/secureauth.db";
        }

        public static final class IdentitySection {
                /**
                 * When true, an account can only be used from connections whose offline UUID
                 * matches the one stored at registration. Offline UUIDs are derived from the
                 * (case-insensitive) username, so mismatches usually mean the server once ran
                 * in a different mode or the name casing changed.
                 */
                public boolean strictUuidBinding = false;
        }

        public static final class AdministrationSection {
                /** Vanilla operator level required for auth.admin.* commands. */
                public int adminOpLevel = 2;
        }

        public static final class LoggingSection {
                public boolean authenticationEvents = true;
                public boolean logToFile = true;
                public String logDir = "logs/secureauth";
                public long maxFileBytes = 5_242_880L; // 5 MiB
                public int maxFiles = 5;
                public boolean logToDatabase = true;
        }

        // ------------------------------------------------------------------
        // Loading
        // ------------------------------------------------------------------

        /** Loads the configuration, writing the default file if it does not exist yet. */
        @SuppressWarnings("unchecked")
        public static AuthConfig load(Path file) throws IOException {
                if (Files.notExists(file)) {
                        Files.createDirectories(file.getParent());
                        Files.writeString(file, defaultYaml(), StandardCharsets.UTF_8);
                }
                Yaml yaml = new Yaml();
                Object rootObj = yaml.load(Files.newBufferedReader(file, StandardCharsets.UTF_8));
                if (!(rootObj instanceof Map<?, ?> root)) {
                        return new AuthConfig();
                }
                AuthConfig cfg = new AuthConfig();
                Map<String, Object> rootMap = (Map<String, Object>) root;

                readAuthentication(section(rootMap, "authentication"), cfg.authentication);
                readPassword(section(rootMap, "password"), cfg.password);
                readSecurity(section(rootMap, "security"), cfg.security);
                readWorldProtection(section(rootMap, "worldProtection"), cfg.worldProtection);
                // 1.2.4 template upgrade: a pre-1.2.4 file knows no "platformBox" key;
                // if it also still carries the old stone default for the platform block,
                // both move to the new bedrock-cell defaults together (an explicit
                // platformBlock in a 1.2.4+ file is always respected verbatim).
                Map<String, Object> wpSection = section(rootMap, "worldProtection");
                if (wpSection != null && !wpSection.containsKey("platformBox")
                                && "minecraft:stone".equals(cfg.worldProtection.platformBlock)) {
                        cfg.worldProtection.platformBlock = "minecraft:bedrock";
                        cfg.upgradedTemplateDefaults = true;
                }
                readWorldInfo(section(rootMap, "worldInfo"), cfg.worldInfo);
                readUi(section(rootMap, "ui"), cfg.ui);
                readStorage(section(rootMap, "storage"), cfg.storage);
                readIdentity(section(rootMap, "identity"), cfg.identity);
                readAdministration(section(rootMap, "administration"), cfg.administration);
                readLogging(section(rootMap, "logging"), cfg.logging);
                // 1.2.2 default migration: an existing file that still carries the exact
                // untouched 1.2.1 template pair (platformY 64 + maxDriftBlocks 8.0) is
                // upgraded to the new sandbox defaults (200 + 1.5). Any other combination
                // counts as a deliberate choice and is respected verbatim.
                if (cfg.worldProtection.platformY == 64 && cfg.worldProtection.maxDriftBlocks == 8.0) {
                        cfg.worldProtection.platformY = 200;
                        cfg.worldProtection.maxDriftBlocks = 1.5;
                        cfg.upgradedTemplateDefaults = true;
                }
                clamp(cfg);
                return cfg;
        }

        private static void readAuthentication(Map<String, Object> m, AuthenticationSection s) {
                if (m == null) return;
                s.enabled = bool(m, "enabled", s.enabled);
                s.timeoutSeconds = int_(m, "timeoutSeconds", s.timeoutSeconds);
                s.autoLoginAfterRegister = bool(m, "autoLoginAfterRegister", s.autoLoginAfterRegister);
                s.warningIntervalSeconds = int_(m, "warningIntervalSeconds", s.warningIntervalSeconds);
                s.sessionPersistSeconds = int_(m, "sessionPersistSeconds", s.sessionPersistSeconds);
                s.sessionRequireSameIp = bool(m, "sessionRequireSameIp", s.sessionRequireSameIp);
        }

        private static void readPassword(Map<String, Object> m, PasswordSection s) {
                if (m == null) return;
                s.algorithm = string(m, "algorithm", s.algorithm);
                s.minimumLength = int_(m, "minimumLength", s.minimumLength);
                s.maximumLength = int_(m, "maximumLength", s.maximumLength);
                Map<String, Object> a = section(m, "argon2");
                if (a != null) {
                        s.argon2.memoryKiB = int_(a, "memoryKiB", s.argon2.memoryKiB);
                        s.argon2.iterations = int_(a, "iterations", s.argon2.iterations);
                        s.argon2.parallelism = int_(a, "parallelism", s.argon2.parallelism);
                        s.argon2.outputLength = int_(a, "outputLength", s.argon2.outputLength);
                        s.argon2.saltLength = int_(a, "saltLength", s.argon2.saltLength);
                }
                Map<String, Object> p = section(m, "pbkdf2");
                if (p != null) {
                        s.pbkdf2.iterations = int_(p, "iterations", s.pbkdf2.iterations);
                        s.pbkdf2.outputLength = int_(p, "outputLength", s.pbkdf2.outputLength);
                        s.pbkdf2.saltLength = int_(p, "saltLength", s.pbkdf2.saltLength);
                }
        }

        private static void readSecurity(Map<String, Object> m, SecuritySection s) {
                if (m == null) return;
                s.maxLoginAttempts = int_(m, "maxLoginAttempts", s.maxLoginAttempts);
                s.lockoutSeconds = int_(m, "lockoutSeconds", s.lockoutSeconds);
                s.kickAfterFailures = int_(m, "kickAfterFailures", s.kickAfterFailures);
                s.perSessionCooldownMs = long_(m, "perSessionCooldownMs", s.perSessionCooldownMs);
                s.ipRateLimit = bool(m, "ipRateLimit", s.ipRateLimit);
                s.ipAuthAttemptsPerMinute = int_(m, "ipAuthAttemptsPerMinute", s.ipAuthAttemptsPerMinute);
                s.ipJoinAttemptsPerMinute = int_(m, "ipJoinAttemptsPerMinute", s.ipJoinAttemptsPerMinute);
                s.permanentLockAfterRepeatedLockouts = bool(m, "permanentLockAfterRepeatedLockouts", s.permanentLockAfterRepeatedLockouts);
                s.lockoutsForPermanentLock = int_(m, "lockoutsForPermanentLock", s.lockoutsForPermanentLock);
                s.lockoutCountWindowSeconds = long_(m, "lockoutCountWindowSeconds", s.lockoutCountWindowSeconds);
        }

        private static void readWorldProtection(Map<String, Object> m, WorldProtectionSection s) {
                if (m == null) return;
                s.isolationMode = string(m, "isolationMode", s.isolationMode);
                s.platformBlock = string(m, "platformBlock", s.platformBlock);
                s.platformRadius = int_(m, "platformRadius", s.platformRadius);
                s.platformY = int_(m, "platformY", s.platformY);
                s.platformBox = bool(m, "platformBox", s.platformBox);
                s.releaseWatchdogSeconds = int_(m, "releaseWatchdogSeconds", s.releaseWatchdogSeconds);
                s.noDamageInSandbox = bool(m, "noDamageInSandbox", s.noDamageInSandbox);
                s.maxDriftBlocks = dbl(m, "maxDriftBlocks", s.maxDriftBlocks);
                s.movementCorrection = bool(m, "movementCorrection", s.movementCorrection);
                s.clearAuthEntities = bool(m, "clearAuthEntities", s.clearAuthEntities);
                s.pureVoid = bool(m, "pureVoid", s.pureVoid);
                s.quarantineBlindness = bool(m, "quarantineBlindness", s.quarantineBlindness);
                s.resetOnRestart = bool(m, "resetOnRestart", s.resetOnRestart);
                s.blockInteraction = bool(m, "blockInteraction", s.blockInteraction);
                s.blockChat = bool(m, "blockChat", s.blockChat);
                s.blockCommands = bool(m, "blockCommands", s.blockCommands);
        }

        private static void readWorldInfo(Map<String, Object> m, WorldInfoSection s) {
                if (m == null) return;
                s.hideTabList = bool(m, "hideTabList", s.hideTabList);
                s.suppressChatBroadcasts = bool(m, "suppressChatBroadcasts", s.suppressChatBroadcasts);
                s.hideMaps = bool(m, "hideMaps", s.hideMaps);
                s.minimalCommandTree = bool(m, "minimalCommandTree", s.minimalCommandTree);
                s.filterScoreboard = bool(m, "filterScoreboard", s.filterScoreboard);
                s.filterCustomPayloads = bool(m, "filterCustomPayloads", s.filterCustomPayloads);
        }

        private static void readUi(Map<String, Object> m, UiSection s) {
                if (m == null) return;
                s.actionBarTimer = bool(m, "actionBarTimer", s.actionBarTimer);
                s.autoOpenAuthPanel = bool(m, "autoOpenAuthPanel", s.autoOpenAuthPanel);
                s.adminPanel = bool(m, "adminPanel", s.adminPanel);
        }

        private static void readStorage(Map<String, Object> m, StorageSection s) {
                if (m == null) return;
                s.databasePath = string(m, "databasePath", s.databasePath);
        }

        private static void readIdentity(Map<String, Object> m, IdentitySection s) {
                if (m == null) return;
                s.strictUuidBinding = bool(m, "strictUuidBinding", s.strictUuidBinding);
        }

        private static void readAdministration(Map<String, Object> m, AdministrationSection s) {
                if (m == null) return;
                s.adminOpLevel = int_(m, "adminOpLevel", s.adminOpLevel);
        }

        private static void readLogging(Map<String, Object> m, LoggingSection s) {
                if (m == null) return;
                s.authenticationEvents = bool(m, "authenticationEvents", s.authenticationEvents);
                s.logToFile = bool(m, "logToFile", s.logToFile);
                s.logDir = string(m, "logDir", s.logDir);
                s.maxFileBytes = long_(m, "maxFileBytes", s.maxFileBytes);
                s.maxFiles = int_(m, "maxFiles", s.maxFiles);
                s.logToDatabase = bool(m, "logToDatabase", s.logToDatabase);
        }

        /** Rejects dangerous nonsense values instead of failing later in strange ways. */
        private static void clamp(AuthConfig cfg) {
                cfg.authentication.timeoutSeconds = Math.max(5, cfg.authentication.timeoutSeconds);
                cfg.authentication.warningIntervalSeconds = Math.max(3, cfg.authentication.warningIntervalSeconds);
                cfg.authentication.sessionPersistSeconds = Math.min(2592000,
                                Math.max(0, cfg.authentication.sessionPersistSeconds));
                cfg.password.minimumLength = Math.max(1, cfg.password.minimumLength);
                cfg.password.maximumLength = Math.min(1024, Math.max(cfg.password.minimumLength, cfg.password.maximumLength));
                cfg.security.maxLoginAttempts = Math.max(1, cfg.security.maxLoginAttempts);
                cfg.security.lockoutSeconds = Math.max(1, cfg.security.lockoutSeconds);
                cfg.security.kickAfterFailures = Math.max(cfg.security.maxLoginAttempts, cfg.security.kickAfterFailures);
                cfg.security.ipAuthAttemptsPerMinute = Math.max(1, cfg.security.ipAuthAttemptsPerMinute);
                cfg.security.ipJoinAttemptsPerMinute = Math.max(1, cfg.security.ipJoinAttemptsPerMinute);
                cfg.worldProtection.platformRadius = Math.min(16, Math.max(1, cfg.worldProtection.platformRadius));
                // The auth dimension spans y 0..255 (height 256, min_y 0); keep the
                // platform comfortably inside and leave room above the player and
                // the cell shell (floor + 3 interior + ceiling = 5 rows).
                cfg.worldProtection.platformY = Math.min(250, Math.max(1, cfg.worldProtection.platformY));
                cfg.worldProtection.releaseWatchdogSeconds = Math.min(60, Math.max(0,
                                cfg.worldProtection.releaseWatchdogSeconds));
                cfg.worldProtection.maxDriftBlocks = Math.max(1.0, cfg.worldProtection.maxDriftBlocks);
                cfg.administration.adminOpLevel = Math.min(4, Math.max(1, cfg.administration.adminOpLevel));
                cfg.logging.maxFiles = Math.max(1, cfg.logging.maxFiles);
                cfg.logging.maxFileBytes = Math.max(65_536L, cfg.logging.maxFileBytes);
                if (!"auth_dimension".equals(cfg.worldProtection.isolationMode)
                                && !"freeze_in_place".equals(cfg.worldProtection.isolationMode)) {
                        cfg.worldProtection.isolationMode = "auth_dimension";
                }
                if (!"argon2id".equalsIgnoreCase(cfg.password.algorithm)
                                && !"pbkdf2".equalsIgnoreCase(cfg.password.algorithm)) {
                        cfg.password.algorithm = "argon2id";
                }
        }

        // ------------------------------------------------------------------
        // Default file
        // ------------------------------------------------------------------

        /**
         * True when untouched older template defaults were upgraded in memory to
         * newer sandbox defaults during {@link #load(Path)}: 1.2.1 → 1.2.2
         * (platformY 64 + maxDriftBlocks 8.0 → 200 + 1.5) and pre-1.2.4 → 1.2.4
         * (platformBlock stone → bedrock for files that predate platformBox).
         * The entrypoint logs it so the admin knows what moved; setting the keys
         * explicitly in the YAML always keeps full control.
         */
        private boolean upgradedTemplateDefaults;

        /** Whether load() upgraded untouched older template defaults to newer values. */
        public boolean upgradedTemplateDefaults() {
                return upgradedTemplateDefaults;
        }

        /** The commented default configuration file. */
        public static String defaultYaml() {
                return """
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
                                  # Holding-cell floor block. Since 1.2.4 the cell is
                                  # unbreakable bedrock: an authenticated player waiting
                                  # inside for the release watchdog can never dig out.
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
                                """;
        }

        // ------------------------------------------------------------------
        // Map helpers
        // ------------------------------------------------------------------

        @SuppressWarnings("unchecked")
        private static Map<String, Object> section(Map<String, Object> map, String key) {
                Object v = map.get(key);
                return v instanceof Map<?, ?> m ? (Map<String, Object>) m : null;
        }

        private static boolean bool(Map<String, Object> map, String key, boolean def) {
                Object v = map.get(key);
                return v instanceof Boolean b ? b : def;
        }

        private static int int_(Map<String, Object> map, String key, int def) {
                Object v = map.get(key);
                if (v instanceof Number n) return n.intValue();
                return def;
        }

        private static long long_(Map<String, Object> map, String key, long def) {
                Object v = map.get(key);
                if (v instanceof Number n) return n.longValue();
                return def;
        }

        private static double dbl(Map<String, Object> map, String key, double def) {
                Object v = map.get(key);
                if (v instanceof Number n) return n.doubleValue();
                return def;
        }

        private static String string(Map<String, Object> map, String key, String def) {
                Object v = map.get(key);
                return v instanceof String s ? s : def;
        }

        /** Serialises this config back to a YAML map (used by tests). */
        public Map<String, Object> toMap() {
                Map<String, Object> root = new LinkedHashMap<>();
                Map<String, Object> auth = new LinkedHashMap<>();
                auth.put("enabled", authentication.enabled);
                auth.put("timeoutSeconds", authentication.timeoutSeconds);
                auth.put("autoLoginAfterRegister", authentication.autoLoginAfterRegister);
                auth.put("warningIntervalSeconds", authentication.warningIntervalSeconds);
                Map<String, Object> tok = new LinkedHashMap<>();
                tok.put("sessionPersistSeconds", authentication.sessionPersistSeconds);
                tok.put("sessionRequireSameIp", authentication.sessionRequireSameIp);
                auth.put("session", tok);
                root.put("authentication", auth);

                DumperOptions options = new DumperOptions();
                options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
                options.setPrettyFlow(true);
                return root;
        }
}
