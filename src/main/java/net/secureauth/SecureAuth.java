package net.secureauth;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import net.fabricmc.api.ModInitializer;
import net.fabricmc.fabric.api.command.v2.CommandRegistrationCallback;
import net.fabricmc.fabric.api.entity.event.v1.ServerLivingEntityEvents;
import net.fabricmc.fabric.api.entity.event.v1.ServerPlayerEvents;
import net.fabricmc.fabric.api.event.lifecycle.v1.ServerLifecycleEvents;
import net.fabricmc.fabric.api.event.lifecycle.v1.ServerTickEvents;
import net.fabricmc.fabric.api.event.player.AttackEntityCallback;
import net.fabricmc.fabric.api.event.player.PlayerBlockBreakEvents;
import net.fabricmc.fabric.api.event.player.UseBlockCallback;
import net.fabricmc.fabric.api.event.player.UseEntityCallback;
import net.fabricmc.fabric.api.event.player.UseItemCallback;
import net.fabricmc.fabric.api.message.v1.ServerMessageEvents;
import net.fabricmc.fabric.api.networking.v1.ServerPlayConnectionEvents;
import net.fabricmc.loader.api.FabricLoader;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.level.ServerPlayer;
import net.minecraft.world.InteractionResult;
import net.minecraft.world.level.storage.LevelResource;
import net.secureauth.account.AccountDatabase;
import net.secureauth.account.AccountRepository;
import net.secureauth.auth.AuthManager;
import net.secureauth.auth.AuthSession;
import net.secureauth.auth.PasswordService;
import net.secureauth.auth.SessionResumeService;
import net.secureauth.command.AuthCommands;
import net.secureauth.config.AuthConfig;
import net.secureauth.lang.Lang;
import net.secureauth.security.LoginAttemptTracker;
import net.secureauth.security.RateLimiter;
import net.secureauth.security.SecurityEvent;
import net.secureauth.security.SecurityLogger;
import net.secureauth.world.AuthWorldManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * SecureAuth server entrypoint: wires the services together and registers all
 * Fabric events. The mod is <strong>server-side only</strong> — every player
 * interaction happens through chat commands and the vanilla-compatible chest
 * panel, so completely unmodified clients can join.
 *
 * <p>When {@code authentication.enabled == false} the mod is completely inert:
 * nothing is registered and every mixin passes straight through. All guards
 * fail closed — a missing manager, disabled mod or missing session always
 * counts as "not authenticated".</p>
 */
public final class SecureAuth implements ModInitializer {

        private static final Logger LOGGER = LoggerFactory.getLogger("secureauth");

        /** Fabric mod id of this mod. */
        public static final String MOD_ID = "secureauth";

        private static volatile SecureAuth instance;

        private volatile boolean enabled;
        private volatile AuthManager authManager;

        private AuthConfig config;
        private AccountDatabase database;
        private SecurityLogger securityLogger;

        public static SecureAuth get() {
                return instance;
        }

        /** False while the mod is disabled (or the server has stopped). */
        public boolean enabled() {
                return enabled;
        }

        /** The manager, or {@code null} while disabled (guards must fail closed). */
        public AuthManager authManager() {
                return enabled ? authManager : null;
        }

        @Override
        public void onInitialize() {
                instance = this;

                // --- 1. Configuration --------------------------------------------------
                Path configFile = FabricLoader.getInstance().getGameDir().resolve("config/secureauth/config.yml");

                // Server-side message catalogs: every player-visible string is resolved
                // here (vanilla clients have no auth.* translations).
                Lang.load();

                AuthConfig loaded;
                boolean configError = false;
                try {
                        loaded = AuthConfig.load(configFile);
                } catch (IOException | RuntimeException e) {
                        LOGGER.warn("Failed to load the SecureAuth configuration; using defaults", e);
                        loaded = new AuthConfig();
                        configError = true;
                }
                this.config = loaded;
                // Keep the mixin-visible entity-birth guard in sync with the config.
                AuthWorldManager.setEntityGuard(loaded.worldProtection.clearAuthEntities);

                if (!loaded.authentication.enabled) {
                        LOGGER.warn("SecureAuth is disabled (authentication.enabled=false): no enforcement is active.");
                        this.enabled = false;
                        return;
                }

                // --- 2. Storage (fail closed when unavailable) ---------------------------
                AccountDatabase db = new AccountDatabase(loaded);
                try {
                        db.open();
                } catch (RuntimeException e) {
                        LOGGER.error("The SecureAuth account database could not be opened; "
                                        + "authentication will fail closed until it recovers.", e);
                }
                this.database = db;

                // --- 3. Services ----------------------------------------------------------
                AccountRepository repository = new AccountRepository(db);
                PasswordService passwords = new PasswordService(loaded);
                if (!passwords.isArgon2Available()) {
                        LOGGER.warn("Argon2id is unavailable: SecureAuth falls back to PBKDF2WithHmacSHA256 for new hashes.");
                }
                SecurityLogger secLogger = new SecurityLogger(loaded, db);
                RateLimiter ipJoinLimiter = new RateLimiter(loaded.security.ipJoinAttemptsPerMinute, 10);
                LoginAttemptTracker tracker = new LoginAttemptTracker(loaded.security.perSessionCooldownMs);
                AuthWorldManager worldManager = new AuthWorldManager(loaded, secLogger);
                SessionResumeService resume = new SessionResumeService(loaded);
                AuthManager manager = new AuthManager(loaded, repository, passwords, secLogger,
                                ipJoinLimiter, tracker, worldManager, resume);
                this.securityLogger = secLogger;
                this.authManager = manager;
                this.enabled = true;

                if (loaded.upgradedTemplateDefaults()) {
                        LOGGER.info("SecureAuth: untouched 1.2.1 template defaults upgraded to 1.2.2 "
                                        + "(platformY 64 -> 200, maxDriftBlocks 8.0 -> 1.5); set these keys "
                                        + "explicitly in secureauth.yml to pin your own values.");
                }
                if (configError) {
                        secLogger.log(SecurityEvent.CONFIG_ERROR, MOD_ID, null, "",
                                        "config_load_failed; using defaults");
                }

                // --- 4. Connection lifecycle ----------------------------------------------
                ServerPlayConnectionEvents.JOIN.register((handler, sender, server) -> {
                        if (handler.player != null) {
                                manager.onJoin(handler.player);
                        }
                });
                ServerPlayConnectionEvents.DISCONNECT.register((handler, server) -> {
                        if (handler.player != null) {
                                manager.onDisconnect(handler.player);
                        }
                });
                ServerTickEvents.END_SERVER_TICK.register(manager::tick);
                // Account-store self-check (since 1.2.4): every 30 seconds the SQLite
                // connection is probed and, when it is unhealthy (I/O hiccup, native
                // error, broken transaction state), transparently closed and reopened.
                // A once-broken store used to stay broken for the rest of the session —
                // every /auth reset answered "service unavailable" — now it heals itself.
                ServerTickEvents.END_SERVER_TICK.register(this::tickStoreHealth);
                // Damage cancellation inside the auth dimension (since 1.2.4): the
                // sandbox is a waiting room. Fall damage from a mid-air rejoin, void
                // damage below the cell, damage from anything else — none of it may
                // ever hurt a player while they are inside secureauth:auth.
                if (loaded.worldProtection.noDamageInSandbox) {
                        ServerLivingEntityEvents.ALLOW_DAMAGE.register((entity, source, amount) -> {
                                if (entity instanceof ServerPlayer player
                                                && player.level().dimension() == AuthWorldManager.AUTH_DIMENSION) {
                                        try {
                                                player.resetFallDistance();
                                        } catch (RuntimeException ignored) {
                                                // Cosmetic best-effort.
                                        }
                                        return false;
                                }
                                return true;
                        });
                }
                // Reset the auth dimension right after the levels are ready but before any
                // player can join: every boot starts from a freshly generated void.
                ServerLifecycleEvents.SERVER_STARTED.register(this::wipeAuthDimension);
                ServerLifecycleEvents.SERVER_STOPPED.register(this::shutdown);

                // --- 5. Respawn guard -----------------------------------------------------
                ServerPlayerEvents.AFTER_RESPAWN.register((oldPlayer, newPlayer, alive) -> manager.onRespawn(oldPlayer, newPlayer));

                // --- 6. Interaction guards ------------------------------------------------
                if (loaded.worldProtection.blockInteraction) {
                        PlayerBlockBreakEvents.BEFORE.register((level, player, pos, state, blockEntity) ->
                                        player instanceof ServerPlayer serverPlayer
                                                        ? interactionGuard(serverPlayer, true)
                                                        : true);
                        UseBlockCallback.EVENT.register((player, level, hand, hitResult) ->
                                        player instanceof ServerPlayer serverPlayer && !interactionGuard(serverPlayer, false)
                                                        ? InteractionResult.FAIL
                                                        : InteractionResult.PASS);
                        UseItemCallback.EVENT.register((player, level, hand) ->
                                        player instanceof ServerPlayer serverPlayer && !interactionGuard(serverPlayer, false)
                                                        ? InteractionResult.FAIL
                                                        : InteractionResult.PASS);
                        AttackEntityCallback.EVENT.register((player, level, hand, entity, hitResult) ->
                                        player instanceof ServerPlayer serverPlayer && !interactionGuard(serverPlayer, false)
                                                        ? InteractionResult.FAIL
                                                        : InteractionResult.PASS);
                        UseEntityCallback.EVENT.register((player, level, hand, entity, hitResult) ->
                                        player instanceof ServerPlayer serverPlayer && !interactionGuard(serverPlayer, false)
                                                        ? InteractionResult.FAIL
                                                        : InteractionResult.PASS);
                }

                // --- 7. Chat guard ----------------------------------------------------------
                if (loaded.worldProtection.blockChat) {
                        ServerMessageEvents.ALLOW_CHAT_MESSAGE.register((message, sender, params) -> {
                                AuthManager live = authManager();
                                if (live == null || live.isAuthenticated(sender)) {
                                        return true;
                                }
                                blockedNotice(live, sender, "auth.chat.blocked");
                                return false;
                        });
                }

                // --- 8. Commands -------------------------------------------------------------
                CommandRegistrationCallback.EVENT.register((dispatcher, buildContext, environment) -> {
                        try {
                                AuthCommands.register(dispatcher);
                        } catch (Exception e) {
                                LOGGER.error("Failed to register the SecureAuth commands", e);
                        }
                });

                // --- 9. Init summary -----------------------------------------------------------
                String version = FabricLoader.getInstance().getModContainer(MOD_ID)
                                .map(container -> container.getMetadata().getVersion().getFriendlyString())
                                .orElse("unknown");
                LOGGER.info("SecureAuth {} initialized (server-side only, server-resolved messages): argon2id={}, "
                                + "isolation mode={}, session resume={}s (same IP), action bar={}, auth panel={}, "
                                + "admin panel={}, pure void={}, entity guard={}, blindness={}, adventure lock, "
                                + "dimension reset on restart={}, platform y={}, bedrock cell={}, release "
                                + "watchdog={}s, no-damage sandbox={}, ability auto-restore outside sandbox, "
                                + "database={}",
                                version,
                                passwords.isArgon2Available(),
                                loaded.worldProtection.isolationMode,
                                loaded.authentication.sessionPersistSeconds,
                                loaded.ui.actionBarTimer,
                                loaded.ui.autoOpenAuthPanel,
                                loaded.ui.adminPanel,
                                loaded.worldProtection.pureVoid,
                                loaded.worldProtection.clearAuthEntities,
                                loaded.worldProtection.quarantineBlindness,
                                loaded.worldProtection.resetOnRestart,
                                loaded.worldProtection.platformY,
                                loaded.worldProtection.platformBox,
                                loaded.worldProtection.releaseWatchdogSeconds,
                                loaded.worldProtection.noDamageInSandbox,
                                loaded.storage.databasePath);
        }

        // ------------------------------------------------------------------
        // Wiring helpers
        // ------------------------------------------------------------------

        /** Tick counter for the periodic store health probe (once per 30 s). */
        private long storeHealthTicks;

        /** Probes the account database connection every 30 seconds and heals it when broken. */
        private void tickStoreHealth(MinecraftServer server) {
                if (database == null || !enabled) {
                        return;
                }
                if (++storeHealthTicks % 600L != 0L) {
                        return;
                }
                try {
                        database.selfCheck();
                } catch (RuntimeException e) {
                        LOGGER.warn("SecureAuth: account store self-check failed; it will fail closed until it recovers", e);
                }
        }

        /**
         * The loaded configuration, or {@code null} before initialisation / while
         * the mod is disabled. Read by mixins that run before the auth manager
         * exists (e.g. the per-boot dimension re-seed during createLevels).
         */
        public AuthConfig config() {
                return config;
        }

        /** Best-effort IP string for security logs (never blank). */
        private static String safeIp(ServerPlayer player) {
                try {
                        String ip = player.getIpAddress();
                        return ip == null ? "unknown" : ip;
                } catch (RuntimeException e) {
                        return "unknown";
                }
        }

        /** True when the interaction may proceed; sends throttled feedback otherwise. */
        private boolean interactionGuard(ServerPlayer player, boolean isBreak) {
                AuthManager manager = authManager();
                if (manager == null) {
                        return true;
                }
                if (manager.isAuthenticated(player)) {
                        return true;
                }
                AuthSession session = manager.session(player);
                boolean notified = false;
                if (session != null) {
                        notified = blockedNotice(manager, player, "auth.interaction.blocked");
                }
                // Log only real break attempts (and only when the throttle let the notice
                // through) to avoid log flooding from interaction spam.
                if (isBreak && notified && session != null) {
                        manager.logger().log(SecurityEvent.SANDBOX_ESCAPE_CORRECTED, session.usernameNorm, null,
                                        session.ip, "break_blocked");
                }
                return false;
        }

        /** Sends a throttled (max 1 per 3 seconds) "blocked" notice. Returns true when sent. */
        private boolean blockedNotice(AuthManager manager, ServerPlayer player, String key) {
                AuthSession session = manager.session(player);
                if (session == null) {
                        return false;
                }
                long now = System.currentTimeMillis();
                if (now - session.lastBlockedNoticeAt < 3000L) {
                        return false;
                }
                session.lastBlockedNoticeAt = now;
                manager.sendTranslated(player, key);
                return true;
        }

        private void shutdown(MinecraftServer server) {
                if (securityLogger != null) {
                        securityLogger.log(SecurityEvent.SERVER_STOPPED, MOD_ID, "");
                }
                // Reset the auth dimension after everything is saved and closed (since
                // 1.2.2 every restart regenerates the void from scratch: no chunk files,
                // no entities, no accumulated state, no lag growth). The same wipe runs
                // again right after the next server start, so a locked file here simply
                // delays the reset by one boot cycle.
                if (enabled && server != null) {
                        try {
                                clearAuthDimension(server);
                        } catch (RuntimeException e) {
                                LOGGER.warn("SecureAuth: auth-dimension reset skipped", e);
                        }
                }
                if (securityLogger != null) {
                        try {
                                securityLogger.close();
                        } catch (RuntimeException ignored) {
                                // Best effort.
                        }
                }
                if (database != null) {
                        try {
                                database.close();
                        } catch (RuntimeException ignored) {
                                // Best effort.
                        }
                }
                enabled = false;
                authManager = null;
        }

        /** Entry point for the SERVER_STARTED reset (see {@link #clearAuthDimension}). */
        private void wipeAuthDimension(MinecraftServer server) {
                try {
                        clearAuthDimension(server);
                } catch (RuntimeException e) {
                        LOGGER.warn("SecureAuth: startup auth-dimension reset skipped", e);
                }
        }

        /**
         * Resets the auth dimension to a freshly generated void on every server
         * restart (since 1.2.2, {@code worldProtection.resetOnRestart=true}).
         *
         * <p>Every saved chunk file of the auth dimension (region, entities, poi) is
         * deleted on SERVER_STOPPED (after the worlds are flushed and closed) and
         * again on SERVER_STARTED (before the first player can join). Because the
         * generator is flat air, regenerating is free: nothing can be lost, the
         * platform is rebuilt by {@code AuthWorldManager} on the first quarantine,
         * and the dimension's seed is re-randomised per boot by the
         * {@code MinecraftServerMixin} wrap — so every restart produces a fresh,
         * uncorrelated, empty void. This also keeps the dimension's folder from
         * ever accumulating chunk files, so unauthenticated traffic cannot grow
         * saved state (no lag creep from the sandbox).</p>
         *
         * <p>A locked file (antivirus, backup tool, crash) simply delays the wipe
         * to the next start/stop; the runtime purifier in
         * {@code AuthWorldManager} heals whatever a failed wipe leaves behind, so
         * the pure-void contract holds regardless. No marker file is used: the
         * wipe is unconditional and idempotent.</p>
         */
        private void clearAuthDimension(MinecraftServer server) {
                if (!("auth_dimension".equals(config.worldProtection.isolationMode)
                                && config.worldProtection.resetOnRestart)) {
                        return;
                }
                Path dimDir = server.getWorldPath(LevelResource.ROOT)
                                .resolve("dimensions").resolve("secureauth").resolve("auth");
                int removed = 0;
                int failed = 0;
                // Clean up the 1.2.1 migration marker if a previous version left one.
                try {
                        Files.deleteIfExists(dimDir.resolve("void-v3.marker"));
                } catch (IOException ignored) {
                        // Cosmetic only.
                }
                for (String sub : new String[] { "region", "entities", "poi" }) {
                        Path dir = dimDir.resolve(sub);
                        if (!Files.isDirectory(dir)) {
                                continue;
                        }
                        List<Path> victims = new ArrayList<>();
                        try (DirectoryStream<Path> stream = Files.newDirectoryStream(dir, "*.mca")) {
                                stream.forEach(victims::add);
                        } catch (IOException ignored) {
                                continue;
                        }
                        for (Path file : victims) {
                                try {
                                        if (Files.deleteIfExists(file)) {
                                                removed++;
                                        }
                                } catch (IOException lockedOrBusy) {
                                        failed++;
                                }
                        }
                }
                if (failed > 0) {
                        LOGGER.warn("SecureAuth: {} auth-dimension chunk file(s) were locked and could "
                                        + "not be removed; the reset retries on the next start/stop "
                                        + "(the runtime void purifier heals the leftovers meanwhile).", failed);
                }
                if (removed > 0) {
                        LOGGER.info("SecureAuth: auth dimension reset for this boot — removed {} saved "
                                        + "chunk file(s); the void regenerates fresh (platform rebuilt on "
                                        + "first quarantine, fresh random seed).", removed);
                }
        }
}
