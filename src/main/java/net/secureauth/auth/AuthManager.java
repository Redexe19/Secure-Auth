package net.secureauth.auth;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import net.minecraft.network.protocol.game.ClientboundSetActionBarTextPacket;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.level.ServerPlayer;
import net.secureauth.account.Account;
import net.secureauth.account.AccountRepository;
import net.secureauth.account.StoreException;
import net.secureauth.config.AuthConfig;
import net.secureauth.lang.Lang;
import net.secureauth.network.PacketBypass;
import net.secureauth.network.PacketFilterService;
import net.secureauth.security.LoginAttemptTracker;
import net.secureauth.security.RateLimiter;
import net.secureauth.security.SecurityEvent;
import net.secureauth.security.SecurityLogger;
import net.secureauth.ui.AuthPanel;
import net.secureauth.world.AuthWorldManager;

/**
 * Central integration hub of the server-side authentication flow.
 *
 * <p>Owns the per-connection {@link AuthSession} map and orchestrates every
 * state transition: join (quarantine), login/register attempts, logout, password
 * change, unregister, timeout and disconnect. All feedback to the player is
 * produced here — chat messages, the action-bar countdown and the
 * vanilla-compatible chest panel from {@link AuthPanel}. No custom packets
 * exist anywhere in the mod, so it runs against completely unmodified
 * clients.</p>
 *
 * <p>Every guard fails closed: a missing session, a disabled mod, a locked
 * account or an unavailable store is always treated as "not authenticated".</p>
 */
public final class AuthManager {

        /** Minimum interval between two feedback messages for one session (anti chat-spam). */
        private static final long FEEDBACK_MIN_INTERVAL_MS = 300L;

        private final AuthConfig config;
        private final AccountRepository repository;
        private final PasswordService passwords;
        private final SecurityLogger logger;
        private final RateLimiter ipJoinLimiter;
        private final LoginAttemptTracker tracker;
        private final AuthWorldManager worldManager;
        private final SessionResumeService resume;

        private final RateLimiter ipAuthLimiter;
        private final LoginService loginService;
        private final RegistrationService registrationService;
        private final PacketFilterService packetFilter;

        private final Map<UUID, AuthSession> sessions = new ConcurrentHashMap<>();

        private long lastSecondAt;
        private long tickCounter;

        public AuthManager(AuthConfig config, AccountRepository repository,
                        PasswordService passwords, SecurityLogger logger,
                        RateLimiter ipJoinLimiter, LoginAttemptTracker tracker,
                        AuthWorldManager worldManager, SessionResumeService resume) {
                this.config = config;
                this.repository = repository;
                this.passwords = passwords;
                this.logger = logger;
                this.ipJoinLimiter = ipJoinLimiter;
                this.tracker = tracker;
                this.worldManager = worldManager;
                this.resume = resume;

                this.ipAuthLimiter = new RateLimiter(config.security.ipAuthAttemptsPerMinute, 5);
                this.loginService = new LoginService(config, repository, passwords, logger, ipAuthLimiter, tracker);
                this.registrationService = new RegistrationService(config, repository, passwords, logger);
                this.packetFilter = new PacketFilterService(this);
        }

        // ------------------------------------------------------------------
        // Accessors
        // ------------------------------------------------------------------

        public AuthConfig config() {
                return config;
        }

        public SecurityLogger logger() {
                return logger;
        }

        public AccountRepository repository() {
                return repository;
        }

        public PasswordService passwords() {
                return passwords;
        }

        public PacketFilterService packetFilter() {
                return packetFilter;
        }

        public SessionResumeService resume() {
                return resume;
        }

        /**
         * The live session of a connected player, or {@code null}. Every caller must
         * treat {@code null} as "unauthenticated" (fail closed) — never as "allowed".
         */
        public AuthSession session(ServerPlayer player) {
                if (player == null) {
                        return null;
                }
                return sessions.get(player.getUUID());
        }

        /** Server-authoritative authentication state (a missing session is NOT authenticated). */
        public boolean isAuthenticated(ServerPlayer player) {
                AuthSession session = session(player);
                return session != null && session.authenticated();
        }

        // ------------------------------------------------------------------
        // Join / leave
        // ------------------------------------------------------------------

        /**
         * Creates the session for a freshly joined player, quarantines them in the
         * auth area and applies world-information isolation. When the server-side
         * session resume matches (same UUID, same IP, inside the persist window),
         * the join is auto-authenticated instead and no quarantine happens.
         */
        public void onJoin(ServerPlayer player) {
                if (player == null) {
                        return;
                }
                String usernameDisplay = player.getGameProfile().name();
                String usernameNorm = AccountRepository.normalize(usernameDisplay);
                String ip = player.getIpAddress() == null ? "unknown" : player.getIpAddress();
                long now = System.currentTimeMillis();

                // 1. Per-IP join limiter — before anything else.
                if (config.security.ipRateLimit && !ipJoinLimiter.tryAcquire(ip)) {
                        logger.log(SecurityEvent.LOGIN_FAILURE, usernameNorm, null, ip, "join_rate_limited");
                        AuthWorldManager.disconnect(player, Lang.comp(player, "auth.login.rateLimited"));
                        return;
                }

                // 2. Create the session (fail closed when the store is unavailable).
                AuthSession session = new AuthSession(player, usernameNorm, usernameDisplay, ip);
                try {
                        Account account = repository.findByUsernameNorm(usernameNorm).orElse(null);
                        if (account != null) {
                                session.account = account;
                                session.state = (account.locked() || account.inTemporaryLockout(now))
                                                ? AuthState.LOCKED
                                                : AuthState.REGISTERED_NOT_AUTHENTICATED;
                        }
                } catch (StoreException e) {
                        // Fail closed: the session stays UNREGISTERED and quarantined; the player
                        // cannot authenticate until the store recovers.
                        logger.log(SecurityEvent.DATABASE_UNAVAILABLE, usernameNorm, null, ip, "join_lookup");
                }

                // 3. Server-side session resume (same-IP quick re-login, 12 h window by default).
                if (resume.enabled() && session.account != null && !session.account.locked()
                                && !session.account.inTemporaryLockout(now)
                                && resume.matches(player.getUUID(), usernameNorm, ip)) {
                        // The auth-time game type is read BEFORE the record is consumed:
                        // the ability reconciliation needs it as the game-type source
                        // for resumed sessions (they carry no quarantine snapshot).
                        session.resumedGameMode = resume.lastGameMode(player.getUUID());
                        resume.consume(player.getUUID());
                        try {
                                repository.recordLoginSuccess(session.account.id());
                        } catch (StoreException e) {
                                logger.log(SecurityEvent.DATABASE_UNAVAILABLE, usernameNorm, null, ip,
                                                "resume_bookkeeping");
                        }
                        session.state = AuthState.AUTHENTICATED;
                        session.authAtMs = now;
                        sessions.put(player.getUUID(), session);
                        // 1.2.4 self-heal: a trusted rejoin whose save data still points INTO
                        // the auth dimension (the player disconnected while a release was
                        // still pending — e.g. a laggy server ate the transfer) used to spawn
                        // them mid-fall inside the void, taking fall damage. They are moved
                        // back into the real world right here, before they can fall anywhere.
                        try {
                                if (worldManager.rescueFromAuthDimension(player, session)) {
                                        logger.log(SecurityEvent.SANDBOX_ESCAPE_CORRECTED, usernameNorm, ip,
                                                        "resume_stuck_in_auth_dimension; rescued");
                                }
                        } catch (RuntimeException ignored) {
                                // The release watchdog keeps re-checking every second.
                        }
                        logger.log(SecurityEvent.SESSION_RESUMED, usernameNorm, ip);
                        sendTranslated(player, "auth.session.resumed", usernameDisplay);
                        sendActionBar(player, "auth.actionbar.resumed", usernameDisplay);
                        return;
                }

                session.deadline = now + config.authentication.timeoutSeconds * 1000L;
                sessions.put(player.getUUID(), session);

                // 4. Physical quarantine (dimension or freeze-in-place fallback).
                worldManager.quarantine(player, session);

                // 5. World-information isolation.
                applyIsolation(session);

                // 6. Welcome message + authentication prompt (chat + chest panel).
                sendAuthPrompt(session);
        }

        /**
         * Removes the session and clears per-connection trackers (always, even
         * when no session was created). An unauthenticated player who is still
         * physically inside the auth dimension is teleported back to their
         * original location FIRST, so the player-data save triggered by this
         * disconnect records a real-world position — otherwise their next join
         * would spawn them inside the auth void.
         */
        public void onDisconnect(ServerPlayer player) {
                if (player == null) {
                        return;
                }
                AuthSession session = sessions.get(player.getUUID());
                if (session != null) {
                        if (session.authenticated()) {
                                // Remember the identity for the session-resume window (12 h default).
                                // The game type handed over is the AUTH-TIME truth — never the live
                                // value, which a missed restore could have left at the sandbox's
                                // adventure (a rejoin would then "remember" the poison as truth).
                                net.minecraft.world.level.GameType truth = session.resumedGameMode;
                                if (truth == null) {
                                        truth = player.gameMode.getGameModeForPlayer();
                                }
                                resume.recordAuthenticated(player.getUUID(), session.usernameNorm, session.ip, truth);
                                // 1.2.4: an authenticated player who is STILL inside the auth
                                // dimension at disconnect (a laggy server ate the release
                                // transfer) gets the same pre-save position repair as the
                                // unauthenticated — their save data must never record the
                                // auth dimension as the place to spawn the next join.
                                if (player.level().dimension() == AuthWorldManager.AUTH_DIMENSION) {
                                        try {
                                                worldManager.restoreOnDisconnect(player, session);
                                        } catch (RuntimeException ignored) {
                                                // The resume rescue on the next join covers the rest.
                                        }
                                }
                        } else {
                                try {
                                        worldManager.restoreOnDisconnect(player, session);
                                } catch (RuntimeException ignored) {
                                        // Best-effort position repair; the capture guard in
                                        // quarantine() covers the residual case on the next join.
                                }
                        }
                }
                tracker.clear(player.getUUID());
                sessions.remove(player.getUUID());
        }

        /**
         * Re-binds the session to the new {@link ServerPlayer} entity created by a
         * respawn. The unauthenticated are re-quarantined (a respawn would otherwise
         * place them into the real world); the authenticated simply continue.
         */
        public void onRespawn(ServerPlayer oldPlayer, ServerPlayer newPlayer) {
                if (newPlayer == null) {
                        return;
                }
                AuthSession previous = sessions.get(newPlayer.getUUID());
                if (previous == null) {
                        return;
                }
                AuthSession session = new AuthSession(newPlayer, previous.usernameNorm, previous.usernameDisplay,
                                previous.ip);
                session.account = previous.account;
                session.state = previous.state;
                session.deadline = previous.deadline;
                session.lastTimeoutWarningAt = previous.lastTimeoutWarningAt;
                session.authAtMs = previous.authAtMs;
                session.openPanel = null;
                sessions.put(newPlayer.getUUID(), session);

                if (!session.authenticated()) {
                        worldManager.quarantine(newPlayer, session);
                        applyIsolation(session);
                        sendAuthPrompt(session);
                }
        }

        // ------------------------------------------------------------------
        // Tick
        // ------------------------------------------------------------------

        /**
         * Called every server tick: per-session world enforcement, timeout warnings
         * and deadline kicks on a ~1 second cadence, plus periodic housekeeping.
         */
        public void tick(MinecraftServer server) {
                if (server == null) {
                        return;
                }

                // Movement / dimension-escape correction every tick (skips authenticated sessions).
                if (!sessions.isEmpty()) {
                        for (AuthSession session : sessions.values()) {
                                try {
                                        // Re-bind to the LIVE player entity: a cross-dimension
                                        // teleport (vanilla /tp, another mod, or a half-finished
                                        // release transfer) can recreate the ServerPlayer and swap
                                        // the connection's reference while the session still holds
                                        // the discarded entity — and ServerPlayer.teleport()
                                        // silently no-ops for removed entities, so every guard
                                        // below (drift, escape, release watchdog) would act on a
                                        // ghost. The connection's public player field is the one
                                        // reference vanilla itself keeps up to date.
                                        ServerPlayer live = session.player;
                                        try {
                                                ServerPlayer viaConnection = live.connection.player;
                                                if (viaConnection != null && !viaConnection.isRemoved()) {
                                                        live = viaConnection;
                                                }
                                        } catch (RuntimeException ignored) {
                                                // Fall back to the player list below.
                                        }
                                        if (live == null || live.isRemoved()) {
                                                live = server.getPlayerList().getPlayer(session.player.getUUID());
                                        }
                                        if (live != null && live != session.player) {
                                                session.player = live;
                                        }
                                        worldManager.tick(session);
                                } catch (RuntimeException ignored) {
                                        // One broken session must never kill the server tick loop.
                                }
                        }
                }

                // Timeout warnings + deadline kicks, at most once per second.
                long now = System.currentTimeMillis();
                if (now - lastSecondAt >= 1000L) {
                        lastSecondAt = now;

                        // Release watchdog (since 1.2.4): an authenticated player must
                        // NEVER remain physically inside the auth dimension. When the
                        // release teleport fails (extreme server or client lag — the
                        // transfer silently no-ops), the player would otherwise be stuck
                        // in the sandbox with all restrictions lifted, free to walk off
                        // the platform into the void. Every second, anyone who has been
                        // authenticated for longer than releaseWatchdogSeconds (5 s
                        // default) and is still inside the dimension is automatically
                        // sent back to where they were; the check repeats every second
                        // until the transfer actually sticks.
                        int watchdogSeconds = config.worldProtection.releaseWatchdogSeconds;
                        if (watchdogSeconds > 0) {
                                for (AuthSession session : sessions.values()) {
                                        if (!session.authenticated() || session.authAtMs == 0
                                                        || now - session.authAtMs < watchdogSeconds * 1000L) {
                                                continue;
                                        }
                                        ServerPlayer player = session.player;
                                        if (player.level().dimension() != AuthWorldManager.AUTH_DIMENSION) {
                                                continue;
                                        }
                                        boolean rescued = false;
                                        try {
                                                rescued = worldManager.rescueFromAuthDimension(player, session);
                                        } catch (RuntimeException ignored) {
                                                // Retried on the next one-second pass.
                                        }
                                        if (rescued) {
                                                if (now - session.lastRescueLogAt >= 5000L) {
                                                        session.lastRescueLogAt = now;
                                                        logger.log(SecurityEvent.SANDBOX_ESCAPE_CORRECTED,
                                                                        session.usernameNorm, session.ip,
                                                                        "release_watchdog_rescued");
                                                }
                                                if (now - session.lastRescueNoticeAt >= 5000L) {
                                                        session.lastRescueNoticeAt = now;
                                                        sendTranslated(player, "auth.release.rescued");
                                                }
                                        }
                                }
                        }

                        // Ability reconciliation (the mirror image of the release
                        // watchdog): the sandbox's entity-level restrictions
                        // (adventure game type, blindness, invulnerable/no-gravity)
                        // are lifted exactly ONCE, at auth success. When that single
                        // restore ever misses the live entity (a cross-dimension
                        // teleport recreated the ServerPlayer between ticks) or
                        // half-fails under lag, the player would walk the real world
                        // forever unable to interact or break blocks — while the
                        // packet-level restores (tab list, scoreboard) always went
                        // through the connection, which is exactly what "the tab
                        // came back but the abilities did not" looks like. Every
                        // second, an authenticated player who is OUTSIDE the auth
                        // dimension is checked once: any sandbox residue still
                        // present is repaired from the pre-quarantine snapshot.
                        // One-shot per quarantine (see reconcileOutsideSandbox) so
                        // later operator changes are never fought.
                        for (AuthSession session : sessions.values()) {
                                if (!session.authenticated() || session.abilitiesReconciled) {
                                        continue;
                                }
                                ServerPlayer player = session.player;
                                if (player == null || player.level().dimension() == AuthWorldManager.AUTH_DIMENSION) {
                                        // Still inside: the release watchdog owns that case.
                                        continue;
                                }
                                boolean repaired;
                                try {
                                        repaired = worldManager.reconcileOutsideSandbox(player, session);
                                } catch (RuntimeException ignored) {
                                        // Retried on the next one-second pass.
                                        continue;
                                }
                                if (repaired) {
                                        logger.log(SecurityEvent.SANDBOX_ESCAPE_CORRECTED,
                                                        session.usernameNorm, session.ip,
                                                        "restricted_outside_sandbox; abilities_restored");
                                        sendTranslated(player, "auth.restore.abilities");
                                }
                                session.abilitiesReconciled = true;
                        }

                        for (AuthSession session : sessions.values()) {
                                if (session.authenticated()) {
                                        continue;
                                }
                                if (now >= session.deadline) {
                                        if (sessions.remove(session.player.getUUID(), session)) {
                                                logger.log(SecurityEvent.AUTH_TIMEOUT, session.usernameNorm, session.ip);
                                        }
                                        // Teleport back to the original location before the kick, so the
                                        // disconnect save does not record the auth dimension as the player's
                                        // position (a rejoin would otherwise spawn them inside the void).
                                        try {
                                                worldManager.restoreOnDisconnect(session.player, session);
                                        } catch (RuntimeException ignored) {
                                                // Best-effort position repair before the kick.
                                        }
                                        AuthWorldManager.disconnect(session.player,
                                                        Lang.comp(session.player, "auth.timeout.kick"));
                                        continue;
                                }
                                int interval = config.authentication.warningIntervalSeconds;
                                if (config.ui.actionBarTimer) {
                                        // Countdown + hint live on the action bar (once per second);
                                        // chat stays clean for real conversation and the panel.
                                        sendAuthActionBar(session, now);
                                } else if (interval > 0 && now - session.lastTimeoutWarningAt >= interval * 1000L) {
                                        session.lastTimeoutWarningAt = now;
                                        sendTranslated(session.player, "auth.timeout.warning", session.secondsUntilDeadline());
                                }
                        }
                }

                // Periodic housekeeping.
                tickCounter++;
                if (tickCounter % 20 == 0) {
                        // Once per second: keep the auth dimension a pure void (blocks) and free
                        // of non-player entities (legacy saves, other mods, failed spawns).
                        try {
                                worldManager.sweepAuthEntities(server);
                        } catch (RuntimeException ignored) {
                                // Sweeping is best-effort.
                        }
                        try {
                                worldManager.purifyVoid(server);
                        } catch (RuntimeException ignored) {
                                // Purifying is best-effort and budgeted per pass.
                        }
                }
                if (tickCounter % 600 == 0 && resume.enabled()) {
                        try {
                                resume.clearExpired();
                        } catch (RuntimeException ignored) {
                                // Pure in-memory housekeeping; nothing to fail.
                        }
                }
        }

        // ------------------------------------------------------------------
        // Authentication flows (all feedback is produced here)
        // ------------------------------------------------------------------

        /** Handles a password login attempt (from the /login command). */
        public void handleLogin(AuthSession session, String password) {
                if (session == null) {
                        return;
                }
                ServerPlayer player = session.player;
                if (session.authenticated()) {
                        sendTranslated(player, "auth.alreadyAuthenticated");
                        return;
                }

                LoginService.Result result = loginService.attempt(session, password);
                if (result instanceof LoginService.Result.Success) {
                        onAuthSuccess(session, "auth.login.success", session.usernameDisplay);
                } else if (result instanceof LoginService.Result.Failure failure) {
                        String arg = failure.arg() == null ? null : String.valueOf(failure.arg());
                        feedback(session, failure.messageKey(), arg);
                } else {
                        // StorageError — fail closed with a storage message.
                        feedback(session, "auth.login.storageError", null);
                }
        }

        /** Handles a registration attempt (from the /register command). */
        public void handleRegister(AuthSession session, String password, String confirmation) {
                if (session == null) {
                        return;
                }
                ServerPlayer player = session.player;
                if (session.authenticated()) {
                        sendTranslated(player, "auth.register.notAllowed");
                        return;
                }

                // Per-session cooldown: registration hashes with Argon2id, so rapid retries
                // must not be able to turn into a CPU denial of service.
                if (!tracker.tryBeginAttempt(player.getUUID())) {
                        feedback(session, "auth.login.cooldown",
                                        tracker.cooldownRemainingSeconds(player.getUUID()));
                        return;
                }

                RegistrationService.Result result = registrationService.register(session, password, confirmation);
                switch (result) {
                        case OK -> onAuthSuccess(session, "auth.register.success", null);
                        case OK_NO_AUTO_LOGIN -> {
                                session.state = AuthState.REGISTERED_NOT_AUTHENTICATED;
                                sendTranslated(player, "auth.register.successNoAuto");
                                sendAuthPrompt(session);
                        }
                        case MISMATCH -> feedback(session, "auth.register.mismatch", null);
                        case TOO_SHORT -> feedback(session, "auth.register.tooShort", config.password.minimumLength);
                        case TOO_LONG -> feedback(session, "auth.register.tooLong", config.password.maximumLength);
                        case ALREADY_EXISTS -> feedback(session, "auth.register.exists", null);
                        case NOT_ELIGIBLE -> feedback(session, "auth.register.notAllowed", null);
                        case STORAGE_ERROR -> feedback(session, "auth.register.failed", null);
                        default -> feedback(session, "auth.register.failed", null);
                }
        }

        /** Logs an authenticated player out and returns them to the auth sandbox. */
        public void logout(ServerPlayer player) {
                if (player == null) {
                        return;
                }
                AuthSession session = session(player);
                if (session == null || !session.authenticated()) {
                        sendTranslated(player, "auth.notAuthenticated");
                        return;
                }

                // A manual logout must never be auto-resumed by the session window.
                resume.invalidate(player.getUUID());

                // Fresh deadline so the timeout applies to the re-authentication too.
                session.state = AuthState.REGISTERED_NOT_AUTHENTICATED;
                session.deadline = System.currentTimeMillis() + config.authentication.timeoutSeconds * 1000L;
                session.lastTimeoutWarningAt = 0L;

                // quarantine() captures a FRESH original location while the player is
                // still in the real world, then moves them back into the auth area.
                worldManager.quarantine(session.player, session);
                applyIsolation(session);
                sendAuthPrompt(session);
                sendTranslated(session.player, "auth.logout.success");
        }

        /** Changes the password of the authenticated account of {@code session}. */
        public void changePassword(AuthSession session, String oldPassword, String newPassword) {
                if (session == null) {
                        return;
                }
                ServerPlayer player = session.player;
                if (!session.authenticated()) {
                        sendTranslated(player, "auth.notAuthenticated");
                        return;
                }
                Account account = session.account;
                if (account == null || oldPassword == null || newPassword == null) {
                        sendTranslated(player, "auth.storage.unavailable");
                        return;
                }

                PasswordService.PasswordHash stored = new PasswordService.PasswordHash(
                                account.algorithm(), account.hashVersion(), account.salt(), account.hash(), account.hashParams());
                if (!passwords.verify(stored, oldPassword)) {
                        sendTranslated(player, "auth.changepassword.wrongOld");
                        return;
                }
                if (newPassword.equals(oldPassword)) {
                        sendTranslated(player, "auth.changepassword.same");
                        return;
                }
                PasswordPolicy.Result policy = new PasswordPolicy(config.password).validate(newPassword);
                if (policy == PasswordPolicy.Result.TOO_SHORT) {
                        sendTranslated(player, "auth.register.tooShort", config.password.minimumLength);
                        return;
                }
                if (policy == PasswordPolicy.Result.TOO_LONG) {
                        sendTranslated(player, "auth.register.tooLong", config.password.maximumLength);
                        return;
                }

                try {
                        PasswordService.PasswordHash fresh = passwords.hash(newPassword);
                        repository.updatePassword(account.id(), fresh);
                        // Refresh the cached account so later verifications use the new hash.
                        try {
                                repository.findByUsernameNorm(session.usernameNorm).ifPresent(refreshed -> session.account = refreshed);
                        } catch (StoreException ignored) {
                                // The password WAS changed; only the cache refresh failed.
                        }
                        // A changed credential invalidates any live session-resume window.
                        resume.invalidate(player.getUUID());
                        logger.log(SecurityEvent.PASSWORD_CHANGED, session.usernameNorm, session.ip);
                        sendTranslated(player, "auth.changepassword.success");
                } catch (StoreException e) {
                        logger.log(SecurityEvent.DATABASE_UNAVAILABLE, session.usernameNorm, null, session.ip, "change_password");
                        sendTranslated(player, "auth.storage.unavailable");
                }
        }

        /** Deletes the account of the authenticated {@code session} after password verification. */
        public void unregister(AuthSession session, String password) {
                if (session == null) {
                        return;
                }
                ServerPlayer player = session.player;
                if (!session.authenticated()) {
                        sendTranslated(player, "auth.notAuthenticated");
                        return;
                }
                Account account = session.account;
                if (account == null || password == null) {
                        sendTranslated(player, "auth.storage.unavailable");
                        return;
                }

                PasswordService.PasswordHash stored = new PasswordService.PasswordHash(
                                account.algorithm(), account.hashVersion(), account.salt(), account.hash(), account.hashParams());
                if (!passwords.verify(stored, password)) {
                        sendTranslated(player, "auth.login.incorrect");
                        return;
                }

                try {
                        repository.delete(account.id());
                } catch (StoreException e) {
                        logger.log(SecurityEvent.DATABASE_UNAVAILABLE, session.usernameNorm, null, session.ip, "unregister");
                        sendTranslated(player, "auth.storage.unavailable");
                        return;
                }

                // Back to the unregistered sandbox state (re-quarantine: the player is
                // currently in the real world and must not stay there unauthenticated).
                session.account = null;
                session.state = AuthState.UNREGISTERED;
                session.deadline = System.currentTimeMillis() + config.authentication.timeoutSeconds * 1000L;
                session.lastTimeoutWarningAt = 0L;
                tracker.clear(player.getUUID());
                resume.invalidate(player.getUUID());
                worldManager.quarantine(player, session);
                applyIsolation(session);
                sendAuthPrompt(session);
                sendTranslated(player, "auth.unregister.success");
        }

        // ------------------------------------------------------------------
        // Feedback helpers
        // ------------------------------------------------------------------

        /**
         * Sends a branded chat message resolved server-side into literal text
         * (bypasses the outgoing packet filter). Vanilla clients have none of
         * the {@code auth.*} translations, so translatable components would
         * render as raw keys — everything the player sees must be fully
         * resolved before it leaves the server. {@code null} arguments are
         * rendered as empty strings, never as the encoder-breaking null that
         * used to kill the {@code system_chat} packet.
         */
        public void sendTranslated(ServerPlayer player, String key, Object... args) {
                if (player == null || key == null) {
                        return;
                }
                PacketBypass.run(() -> player.sendSystemMessage(Lang.comp(player, key, args), false));
        }

        /**
         * Sends the authentication prompt: the welcome chat line with the command
         * instructions, plus (when enabled and not yet shown) the chest auth panel
         * that vanilla clients render as an ordinary chest menu.
         */
        public void sendAuthPrompt(AuthSession session) {
                if (session == null) {
                        return;
                }
                ServerPlayer player = session.player;

                // Chat prompt for everyone.
                if (session.state == AuthState.LOCKED && session.account != null) {
                        if (session.account.locked()) {
                                sendTranslated(player, "auth.login.lockedPermanent");
                        } else {
                                long seconds = Math.max(0L,
                                                (session.account.lockoutUntil() - System.currentTimeMillis() + 999L) / 1000L);
                                sendTranslated(player, "auth.welcome.locked", seconds);
                        }
                } else if (session.account == null) {
                        sendTranslated(player, "auth.welcome.new");
                } else {
                        sendTranslated(player, "auth.welcome.returning");
                }

                // Action bar: the countdown + command hint starts immediately (once per
                // second afterwards from the tick loop), keeping the chat clean.
                if (config.ui.actionBarTimer && !session.authenticated()) {
                        sendAuthActionBar(session, System.currentTimeMillis());
                }

                // Chest panel: refreshed when already open, auto-opened on join.
                if (config.ui.autoOpenAuthPanel && !session.authenticated() && session.openPanel == null) {
                        AuthPanel.open(this, session);
                } else if (session.openPanel != null) {
                        AuthPanel.refresh(session);
                }
        }

        // ------------------------------------------------------------------
        // Internals
        // ------------------------------------------------------------------

        /** Full post-authentication flow: restore world, restore info, feedback, panel close. */
        private void onAuthSuccess(AuthSession session, String messageKey, String messageArg) {
                ServerPlayer player = session.player;
                session.state = AuthState.AUTHENTICATED;
                // The release watchdog starts here: if the dimension transfer below
                // fails under lag, the player is auto-rescued 5 seconds later.
                session.authAtMs = System.currentTimeMillis();

                // 1. Restore the player into the real world.
                worldManager.restore(player, session);
                // The auth-time game type (the post-restore value) becomes the truth for
                // the resume record and for the ability reconciliation of a future
                // resumed session — the snapshot's value was applied to THIS entity, so
                // reading it back here captures the truth even when the restore acted on
                // a stale entity (the live one keeps the residue; the reconciliation then
                // has this remembered value to repair it against).
                try {
                        session.resumedGameMode = player.gameMode.getGameModeForPlayer();
                } catch (RuntimeException ignored) {
                        // Reading the game type is best-effort; the snapshot still covers it.
                }

                // 2. Undo the world-information isolation. Since 1.2.3 this also
                // re-syncs what the filter ate while the player was quarantined:
                // listed tab entries (previously unlisted → "empty tab until
                // rejoin"), any scoreboard objectives created meanwhile, and the
                // full data of carried maps.
                MinecraftServer server = player.level().getServer();
                if (server != null) {
                        packetFilter.restoreOtherPlayers(player, server);
                        packetFilter.restoreScoreboard(player, server);
                }
                packetFilter.resendMapData(player);
                packetFilter.restoreCommandTree(player);

                // 3. Close the auth chest panel (a lingering open panel is confusing).
                AuthPanel.close(session);

                // 4. Success feedback.
                sendTranslated(player, messageKey, messageArg);
                // 5. Action bar confirmation (fades by itself; the per-second countdown stops).
                sendActionBar(player, "auth.actionbar.done", session.usernameDisplay);
        }

        /** Throttled failure feedback: chat message + live refresh of an open panel. */
        private void feedback(AuthSession session, String key, Object arg) {
                long now = System.currentTimeMillis();
                if (now - session.lastFeedbackAt < FEEDBACK_MIN_INTERVAL_MS) {
                        return;
                }
                session.lastFeedbackAt = now;
                sendTranslated(session.player, key, arg);
                // Keep an open panel in sync with the new attempt/lock state.
                if (session.openPanel != null) {
                        AuthPanel.refresh(session);
                }
        }

        // ------------------------------------------------------------------
        // Action bar (vanilla-compatible: sits above the hotbar, fades by itself)
        // ------------------------------------------------------------------

        /**
         * One action-bar line per second while unauthenticated: the state hint
         * plus the deadline countdown (or the lockout timer). This replaces the
         * periodic chat warnings — the chat stays clean for the welcome line,
         * the chest panel and real conversation.
         */
        private void sendAuthActionBar(AuthSession session, long now) {
                ServerPlayer player = session.player;
                if (player == null) {
                        return;
                }
                long seconds = session.secondsUntilDeadline();
                String key;
                Object arg = seconds;
                if (seconds > 0 && seconds <= 10) {
                        key = "auth.actionbar.urgent";
                } else if (session.account != null && session.account.locked()) {
                        key = "auth.actionbar.lockedPermanent";
                        arg = null;
                } else if (session.account != null && session.account.inTemporaryLockout(now)) {
                        key = "auth.actionbar.locked";
                        arg = Math.max(0L, (session.account.lockoutUntil() - now + 999L) / 1000L);
                } else if (session.account == null) {
                        key = "auth.actionbar.register";
                } else {
                        key = "auth.actionbar.login";
                }
                sendActionBar(player, key, arg);
        }

        /** Sends a resolved literal action-bar line (no custom packets, unmodified clients render it). */
        private void sendActionBar(ServerPlayer player, String key, Object... args) {
                try {
                        // Unbranded on purpose: the action bar sits above the hotbar where
                        // the [SecureAuth] prefix would only waste precious space.
                        player.connection.send(new ClientboundSetActionBarTextPacket(Lang.plain(player, key, args)));
                } catch (RuntimeException ignored) {
                        // The action bar is cosmetic; it must never break the auth flow.
                }
        }

        private void applyIsolation(AuthSession session) {
                ServerPlayer player = session.player;
                MinecraftServer server = player.level().getServer();
                if (server == null) {
                        return;
                }
                if (config.worldInfo.hideTabList) {
                        packetFilter.hideOtherPlayers(player, server);
                }
                if (config.worldInfo.minimalCommandTree) {
                        packetFilter.sendMinimalCommandTree(player);
                }
        }
}
