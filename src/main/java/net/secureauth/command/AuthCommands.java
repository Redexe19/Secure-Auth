package net.secureauth.command;

import com.mojang.brigadier.Command;
import com.mojang.brigadier.CommandDispatcher;
import com.mojang.brigadier.arguments.IntegerArgumentType;
import com.mojang.brigadier.arguments.StringArgumentType;
import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import net.fabricmc.loader.api.FabricLoader;
import net.minecraft.commands.CommandSourceStack;
import net.minecraft.commands.Commands;
import net.minecraft.server.level.ServerPlayer;
import net.minecraft.server.permissions.Permission;
import net.minecraft.server.permissions.PermissionLevel;
import net.secureauth.SecureAuth;
import net.secureauth.account.Account;
import net.secureauth.account.AccountRepository;
import net.secureauth.account.StoreException;
import net.secureauth.auth.AuthManager;
import net.secureauth.auth.AuthSession;
import net.secureauth.auth.AuthState;
import net.secureauth.auth.PasswordPolicy;
import net.secureauth.auth.PasswordService;
import net.secureauth.config.AuthConfig;
import net.secureauth.lang.Lang;
import net.secureauth.security.SecurityEvent;
import net.secureauth.ui.AdminPanel;
import net.secureauth.ui.AuthPanel;
import net.secureauth.world.AuthWorldManager;

/**
 * All SecureAuth commands.
 *
 * <p>User commands ({@code /register}, {@code /login}, {@code /logout},
 * {@code /changepassword}, {@code /unregister}) are thin forwarders: every
 * piece of feedback for them is produced by {@link AuthManager}, which sends
 * chat and GUI results itself. This class only adds argument validation
 * (password confirmation) and the session-state gate for registration.</p>
 *
 * <p>{@code /auth …} is the administration interface, gated by the vanilla
 * permission level configured in {@code administration.adminOpLevel}. Its
 * feedback is sent through {@link AuthManager#sendTranslated} when the
 * administrator is a player, and as plain system messages when it is the
 * console.</p>
 *
 * <p>Security rules enforced here:</p>
 * <ul>
 *   <li>Password arguments are {@code word()} arguments, never greedy — the
 *       confirmation argument would otherwise swallow the rest of the line.</li>
 *   <li>No feedback path ever echoes a password back to the sender.</li>
 *   <li>Every repository access is wrapped so a database failure degrades into
 *       a translated "service unavailable" reply instead of an exception
 *       bubbling into the command dispatcher (fail closed, never fail open).</li>
 *   <li>Missing session, disabled mod or a null manager is treated as
 *       "not authenticated" — never as success.</li>
 * </ul>
 */
public final class AuthCommands {

        /** Accounts shown per page by {@code /auth list}. */
        private static final int PAGE_SIZE = 10;

        private AuthCommands() {
        }

        // ------------------------------------------------------------------
        // Registration
        // ------------------------------------------------------------------

        /**
         * Registers all SecureAuth commands into the server command dispatcher.
         * Called by {@code CommandRegistrationCallback} during server start.
         */
        public static void register(CommandDispatcher<CommandSourceStack> dispatcher) {
                registerUserCommands(dispatcher);
                registerAdminCommands(dispatcher);
        }

        private static void registerUserCommands(CommandDispatcher<CommandSourceStack> dispatcher) {
                // /register <password> <confirm>
                dispatcher.register(Commands.literal("register")
                                .then(Commands.argument("password", StringArgumentType.word())
                                                .then(Commands.argument("confirm", StringArgumentType.word())
                                                                .executes(context -> register(context.getSource(),
                                                                                StringArgumentType.getString(context, "password"),
                                                                                StringArgumentType.getString(context, "confirm"))))));

                // /login <password>
                dispatcher.register(Commands.literal("login")
                                .then(Commands.argument("password", StringArgumentType.word())
                                                .executes(context -> login(context.getSource(),
                                                                StringArgumentType.getString(context, "password")))));

                // /logout
                dispatcher.register(Commands.literal("logout")
                                .executes(context -> logout(context.getSource())));

                // /authpanel — the chest auth panel (vanilla clients see a chest menu)
                dispatcher.register(Commands.literal("authpanel")
                                .executes(context -> openPanel(context.getSource())));

                // /changepassword <oldPassword> <newPassword> <confirm>
                dispatcher.register(Commands.literal("changepassword")
                                .then(Commands.argument("oldPassword", StringArgumentType.word())
                                                .then(Commands.argument("newPassword", StringArgumentType.word())
                                                                .then(Commands.argument("confirm", StringArgumentType.word())
                                                                                .executes(context -> changePassword(context.getSource(),
                                                                                                StringArgumentType.getString(context, "oldPassword"),
                                                                                                StringArgumentType.getString(context, "newPassword"),
                                                                                                StringArgumentType.getString(context, "confirm")))))));

                // /unregister <password>
                dispatcher.register(Commands.literal("unregister")
                                .then(Commands.argument("password", StringArgumentType.word())
                                                .executes(context -> unregister(context.getSource(),
                                                                StringArgumentType.getString(context, "password")))));
        }

        private static void registerAdminCommands(CommandDispatcher<CommandSourceStack> dispatcher) {
                dispatcher.register(Commands.literal("auth")
                                .executes(context -> adminUsage(context.getSource()))
                                .then(Commands.literal("info")
                                                .then(Commands.argument("player", StringArgumentType.word())
                                                                .executes(context -> adminInfo(context.getSource(),
                                                                                StringArgumentType.getString(context, "player")))))
                                .then(Commands.literal("reset")
                                                .then(Commands.argument("player", StringArgumentType.word())
                                                                .then(Commands.argument("newPassword", StringArgumentType.word())
                                                                                .executes(context -> adminReset(context.getSource(),
                                                                                                StringArgumentType.getString(context, "player"),
                                                                                                StringArgumentType.getString(context, "newPassword"))))))
                                .then(Commands.literal("unregister")
                                                .then(Commands.argument("player", StringArgumentType.word())
                                                                .executes(context -> adminUnregister(context.getSource(),
                                                                                StringArgumentType.getString(context, "player")))))
                                .then(Commands.literal("lock")
                                                .then(Commands.argument("player", StringArgumentType.word())
                                                                .executes(context -> adminLock(context.getSource(), true,
                                                                                StringArgumentType.getString(context, "player")))))
                                .then(Commands.literal("unlock")
                                                .then(Commands.argument("player", StringArgumentType.word())
                                                                .executes(context -> adminLock(context.getSource(), false,
                                                                                StringArgumentType.getString(context, "player")))))
                                .then(Commands.literal("forcelogout")
                                                .then(Commands.argument("player", StringArgumentType.word())
                                                                .executes(context -> adminForceLogout(context.getSource(),
                                                                                StringArgumentType.getString(context, "player")))))
                                .then(Commands.literal("panel")
                                                .executes(context -> adminPanel(context.getSource())))
                                .then(Commands.literal("list")
                                                .executes(context -> adminList(context.getSource(), 1))
                                                .then(Commands.argument("page", IntegerArgumentType.integer(1))
                                                                .executes(context -> adminList(context.getSource(),
                                                                                IntegerArgumentType.getInteger(context, "page")))))
                                .then(Commands.literal("reload")
                                                .executes(context -> adminReload(context.getSource()))));
        }

        // ------------------------------------------------------------------
        // User commands (pure forwarders into AuthManager)
        // ------------------------------------------------------------------

        private static int register(CommandSourceStack source, String password, String confirmation) {
                AuthManager manager = manager();
                ServerPlayer player = source.getPlayer();
                if (manager == null || player == null) {
                        // Console or disabled mod: nobody can register from there.
                        return failure(source, "auth.notAuthenticated");
                }
                AuthSession session = manager.session(player);
                if (session == null) {
                        manager.sendTranslated(player, "auth.notAuthenticated");
                        return 0;
                }
                if (session.state != AuthState.UNREGISTERED && session.state != AuthState.REGISTERING) {
                        manager.sendTranslated(player, "auth.register.notAllowed");
                        return 0;
                }
                manager.handleRegister(session, password, confirmation);
                return Command.SINGLE_SUCCESS;
        }

        private static int login(CommandSourceStack source, String password) {
                AuthManager manager = manager();
                ServerPlayer player = source.getPlayer();
                if (manager == null || player == null) {
                        return failure(source, "auth.notAuthenticated");
                }
                AuthSession session = manager.session(player);
                if (session == null) {
                        manager.sendTranslated(player, "auth.notAuthenticated");
                        return 0;
                }
                manager.handleLogin(session, password);
                return Command.SINGLE_SUCCESS;
        }

        private static int logout(CommandSourceStack source) {
                AuthManager manager = manager();
                ServerPlayer player = source.getPlayer();
                if (manager == null || player == null) {
                        return failure(source, "auth.notAuthenticated");
                }
                manager.logout(player);
                return Command.SINGLE_SUCCESS;
        }

        /** Opens the chest auth panel — works on completely vanilla clients. */
        private static int openPanel(CommandSourceStack source) {
                AuthManager manager = manager();
                ServerPlayer player = source.getPlayer();
                if (manager == null) {
                        return failure(source, "auth.storage.unavailable");
                }
                if (player == null) {
                        // A chest menu needs an in-game viewer; console admins get a plain reply.
                        reply(source, manager, "auth.admin.panel.console");
                        return 0;
                }
                AuthSession session = manager.session(player);
                if (session == null) {
                        manager.sendTranslated(player, "auth.notAuthenticated");
                        return 0;
                }
                AuthPanel.open(manager, session);
                return Command.SINGLE_SUCCESS;
        }

        private static int changePassword(CommandSourceStack source, String oldPassword, String newPassword,
                        String confirmation) {
                AuthManager manager = manager();
                ServerPlayer player = source.getPlayer();
                if (manager == null || player == null) {
                        return failure(source, "auth.notAuthenticated");
                }
                AuthSession session = manager.session(player);
                if (session == null) {
                        manager.sendTranslated(player, "auth.notAuthenticated");
                        return 0;
                }
                if (!newPassword.equals(confirmation)) {
                        manager.sendTranslated(player, "auth.register.mismatch");
                        return 0;
                }
                manager.changePassword(session, oldPassword, newPassword);
                return Command.SINGLE_SUCCESS;
        }

        private static int unregister(CommandSourceStack source, String password) {
                AuthManager manager = manager();
                ServerPlayer player = source.getPlayer();
                if (manager == null || player == null) {
                        return failure(source, "auth.notAuthenticated");
                }
                AuthSession session = manager.session(player);
                if (session == null) {
                        manager.sendTranslated(player, "auth.notAuthenticated");
                        return 0;
                }
                manager.unregister(session, password);
                return Command.SINGLE_SUCCESS;
        }

        // ------------------------------------------------------------------
        // /auth administration
        // ------------------------------------------------------------------

        private static int adminUsage(CommandSourceStack source) {
                AuthManager manager = requireManager(source);
                if (manager == null) {
                        return 0;
                }
                if (!requireAdmin(source, manager)) {
                        return 0;
                }
                reply(source, manager, "auth.admin.usage");
                return Command.SINGLE_SUCCESS;
        }

        private static int adminInfo(CommandSourceStack source, String name) {
                AuthManager manager = requireManager(source);
                if (manager == null) {
                        return 0;
                }
                if (!requireAdmin(source, manager)) {
                        return 0;
                }
                Account account = lookupAccount(source, manager, name);
                if (account == null) {
                        return 0;
                }
                long now = System.currentTimeMillis();
                boolean temporaryLockout = account.inTemporaryLockout(now);
                reply(source, manager, "auth.admin.info.header", account.usernameDisplay());
                reply(source, manager, "auth.admin.info.username", account.usernameNorm());
                reply(source, manager, "auth.admin.info.registered", account.registeredAtIso());
                reply(source, manager, "auth.admin.info.lastLogin",
                                account.lastLogin() == null
                                                ? Lang.textForConsole("auth.admin.info.never")
                                                : account.lastLoginIso());
                reply(source, manager, "auth.admin.info.locked", account.locked() ? "yes" : "no");
                reply(source, manager, "auth.admin.info.lockoutUntil",
                                temporaryLockout ? Instant.ofEpochMilli(account.lockoutUntil()).toString()
                                                : Lang.textForConsole("auth.admin.info.never"));
                reply(source, manager, "auth.admin.info.failedAttempts", account.failedAttempts());
                // Only the algorithm name is shown — never salt, hash or parameters.
                reply(source, manager, "auth.admin.info.algorithm", account.algorithm());
                return Command.SINGLE_SUCCESS;
        }

        private static int adminReset(CommandSourceStack source, String name, String newPassword) {
                AuthManager manager = requireManager(source);
                if (manager == null) {
                        return 0;
                }
                if (!requireAdmin(source, manager)) {
                        return 0;
                }
                Account account = lookupAccount(source, manager, name);
                if (account == null) {
                        return 0;
                }
                PasswordPolicy policy = new PasswordPolicy(manager.config().password);
                switch (policy.validate(newPassword)) {
                        case TOO_SHORT -> {
                                reply(source, manager, "auth.register.tooShort", policy.minLength());
                                return 0;
                        }
                        case TOO_LONG -> {
                                reply(source, manager, "auth.register.tooLong", policy.maxLength());
                                return 0;
                        }
                        default -> {
                        }
                }
                try {
                        PasswordService.PasswordHash hash = manager.passwords().hash(newPassword);
                        // updatePassword already zeroes failed_attempts and lockout_until
                        // in the SAME statement — a separate clearLockout call used to run
                        // a second transaction that could fail independently (the flaky
                        // "service unavailable" on reset with nothing actually wrong).
                        manager.repository().updatePassword(account.id(), hash);
                } catch (StoreException e) {
                        logStoreFailure(source, manager, "reset", e);
                        reply(source, manager, "auth.storage.unavailable");
                        return 0;
                }
                // Drop the cached account of an online, still-unauthenticated target so the
                // next attempt re-reads the fresh row (and the new hash) from the database.
                ServerPlayer target = findOnline(source, name);
                if (target != null) {
                        AuthSession session = manager.session(target);
                        if (session != null && !session.authenticated()) {
                                session.account = null;
                        }
                }
                manager.logger().log(SecurityEvent.ADMIN_RESET, actorName(source), account.usernameNorm(),
                                actorIp(source), "password_reset");
                reply(source, manager, "auth.admin.reset.success", account.usernameDisplay());
                return Command.SINGLE_SUCCESS;
        }

        private static int adminUnregister(CommandSourceStack source, String name) {
                AuthManager manager = requireManager(source);
                if (manager == null) {
                        return 0;
                }
                if (!requireAdmin(source, manager)) {
                        return 0;
                }
                Account account = lookupAccount(source, manager, name);
                if (account == null) {
                        return 0;
                }
                ServerPlayer target = findOnline(source, name);
                AuthSession session = target != null ? manager.session(target) : null;
                // A currently playing target is sent back to the sandbox first, so account
                // deletion can never leave an unauthenticated player in the real world.
                if (session != null && session.authenticated()) {
                        manager.logout(target);
                }
                boolean deleted;
                try {
                        deleted = manager.repository().delete(account.id());
                } catch (StoreException e) {
                        logStoreFailure(source, manager, "unregister", e);
                        reply(source, manager, "auth.storage.unavailable");
                        return 0;
                }
                if (!deleted) {
                        reply(source, manager, "auth.admin.unknownPlayer", name);
                        return 0;
                }
                if (session != null) {
                        session.account = null;
                        session.state = AuthState.UNREGISTERED;
                        manager.sendAuthPrompt(session);
                }
                manager.logger().log(SecurityEvent.ADMIN_UNREGISTER, actorName(source), account.usernameNorm(),
                                actorIp(source));
                reply(source, manager, "auth.admin.unregister.success", account.usernameDisplay());
                return Command.SINGLE_SUCCESS;
        }

        private static int adminLock(CommandSourceStack source, boolean lock, String name) {
                AuthManager manager = requireManager(source);
                if (manager == null) {
                        return 0;
                }
                if (!requireAdmin(source, manager)) {
                        return 0;
                }
                Account account = lookupAccount(source, manager, name);
                if (account == null) {
                        return 0;
                }
                try {
                        manager.repository().setLocked(account.id(), lock);
                } catch (StoreException e) {
                        logStoreFailure(source, manager, lock ? "lock" : "unlock", e);
                        reply(source, manager, "auth.storage.unavailable");
                        return 0;
                }
                account.setLocked(lock);
                account.setLockoutUntil(0);
                account.setFailedAttempts(0);

                ServerPlayer target = findOnline(source, name);
                AuthSession session = target != null ? manager.session(target) : null;
                if (session != null) {
                        if (session.account != null) {
                                session.account.setLocked(lock);
                                session.account.setLockoutUntil(0);
                                session.account.setFailedAttempts(0);
                        }
                        if (lock && !session.authenticated()) {
                                session.state = AuthState.LOCKED;
                        } else if (!lock && session.state == AuthState.LOCKED) {
                                session.state = AuthState.REGISTERED_NOT_AUTHENTICATED;
                                manager.sendAuthPrompt(session);
                        }
                }
                manager.logger().log(lock ? SecurityEvent.ACCOUNT_PERMANENTLY_LOCKED : SecurityEvent.ACCOUNT_UNLOCKED,
                                actorName(source), account.usernameNorm(), actorIp(source));
                reply(source, manager, lock ? "auth.admin.lock.success" : "auth.admin.unlock.success",
                                account.usernameDisplay());
                return Command.SINGLE_SUCCESS;
        }

        private static int adminForceLogout(CommandSourceStack source, String name) {
                AuthManager manager = requireManager(source);
                if (manager == null) {
                        return 0;
                }
                if (!requireAdmin(source, manager)) {
                        return 0;
                }
                ServerPlayer target = findOnline(source, name);
                if (target == null) {
                        // No dedicated "player offline" key exists; the unknown-account reply is
                        // the closest generic feedback this mod ships.
                        reply(source, manager, "auth.admin.unknownPlayer", name);
                        return 0;
                }
                AuthSession session = manager.session(target);
                boolean acted = false;
                if (session != null && session.authenticated()) {
                        manager.logout(target);
                        acted = true;
                }
                if (acted) {
                        manager.logger().log(SecurityEvent.ADMIN_FORCE_LOGOUT, actorName(source),
                                        AccountRepository.normalize(name), actorIp(source));
                }
                // Idempotent when the target was already unauthenticated: they are in the
                // authentication area either way.
                reply(source, manager, "auth.admin.forcelogout.success", target.getGameProfile().name());
                return Command.SINGLE_SUCCESS;
        }

        /** /auth panel — the admin chest GUI over the live session table. */
        private static int adminPanel(CommandSourceStack source) {
                AuthManager manager = requireManager(source);
                if (manager == null) {
                        return 0;
                }
                if (!requireAdmin(source, manager)) {
                        return 0;
                }
                if (!manager.config().ui.adminPanel) {
                        reply(source, manager, "auth.admin.panel.disabled");
                        return 0;
                }
                ServerPlayer player = source.getPlayer();
                if (player == null) {
                        // The chest GUI needs a viewer; console admins use the chat subcommands.
                        reply(source, manager, "auth.admin.panel.console");
                        return 0;
                }
                AdminPanel.open(manager, player);
                return Command.SINGLE_SUCCESS;
        }

        private static int adminList(CommandSourceStack source, int page) {
                AuthManager manager = requireManager(source);
                if (manager == null) {
                        return 0;
                }
                if (!requireAdmin(source, manager)) {
                        return 0;
                }
                long total;
                List<String[]> entries;
                int totalPages;
                try {
                        total = manager.repository().countAccounts();
                        totalPages = (int) Math.max(1, (total + PAGE_SIZE - 1) / PAGE_SIZE);
                        if (page > totalPages) {
                                page = totalPages;
                        }
                        entries = manager.repository().listAccounts((page - 1) * PAGE_SIZE, PAGE_SIZE);
                } catch (StoreException e) {
                        logStoreFailure(source, manager, "list", e);
                        reply(source, manager, "auth.storage.unavailable");
                        return 0;
                }
                reply(source, manager, "auth.admin.list.header", page, totalPages);
                for (String[] entry : entries) {
                        reply(source, manager, "auth.admin.list.entry", entry[0], entry[1]);
                }
                return Command.SINGLE_SUCCESS;
        }

        private static int adminReload(CommandSourceStack source) {
                AuthManager manager = requireManager(source);
                if (manager == null) {
                        return 0;
                }
                if (!requireAdmin(source, manager)) {
                        return 0;
                }
                Path configPath = FabricLoader.getInstance().getGameDir().resolve("config/secureauth/config.yml");
                try {
                        AuthConfig fresh = AuthConfig.load(configPath);
                        copyInto(manager.config(), fresh);
                } catch (IOException | RuntimeException e) {
                        manager.logger().log(SecurityEvent.CONFIG_ERROR, actorName(source), null, actorIp(source),
                                        "reload_failed:" + e.getClass().getSimpleName());
                        reply(source, manager, "auth.storage.unavailable");
                        return 0;
                }
                reply(source, manager, "auth.admin.reload.success");
                return Command.SINGLE_SUCCESS;
        }

        // ------------------------------------------------------------------
        // Shared helpers
        // ------------------------------------------------------------------

        /** The live auth manager, or {@code null} when the mod is absent or disabled. */
        private static AuthManager manager() {
                SecureAuth mod = SecureAuth.get();
                return mod != null ? mod.authManager() : null;
        }

        /** Resolves the manager or replies with a generic failure (never returns silently). */
        private static AuthManager requireManager(CommandSourceStack source) {
                AuthManager manager = manager();
                if (manager == null) {
                        source.sendFailure(Lang.compForConsole("auth.storage.unavailable"));
                }
                return manager;
        }

        /**
         * Admin gate: the vanilla permission level configured under
         * {@code administration.adminOpLevel}. Console sources always pass. Sends
         * {@code auth.admin.permission} and returns false when the gate fails —
         * or when the permission subsystem itself misbehaves (fail closed).
         */
        private static boolean requireAdmin(CommandSourceStack source, AuthManager manager) {
                int level = Math.min(4, Math.max(1, manager.config().administration.adminOpLevel));
                boolean allowed;
                try {
                        allowed = source.permissions().hasPermission(new Permission.HasCommandLevel(PermissionLevel.byId(level)));
                } catch (RuntimeException e) {
                        allowed = false;
                }
                if (!allowed) {
                        reply(source, manager, "auth.admin.permission");
                        return false;
                }
                return true;
        }

        /**
         * Sends admin feedback: through the manager (prefixed chat, bypassing the
         * pre-auth packet filter) when the administrator is a player, and as a
         * plain system message when it is the console.
         */
        private static void reply(CommandSourceStack source, AuthManager manager, String key, Object... args) {
                ServerPlayer player = source.getPlayer();
                if (player != null) {
                        manager.sendTranslated(player, key, args);
                        return;
                }
                source.sendSystemMessage(Lang.compForConsole(key, args));
        }

        private static int failure(CommandSourceStack source, String key) {
                source.sendFailure(Lang.compForConsole(key));
                return 0;
        }

        /**
         * Looks up the account for a player name of any casing. Replies with
         * {@code auth.admin.unknownPlayer} (or a storage failure) and returns
         * {@code null} when the account cannot be resolved.
         */
        private static Account lookupAccount(CommandSourceStack source, AuthManager manager, String name) {
                Account account;
                try {
                        account = manager.repository().findByUsernameNorm(AccountRepository.normalize(name)).orElse(null);
                } catch (StoreException e) {
                        logStoreFailure(source, manager, "lookup", e);
                        reply(source, manager, "auth.storage.unavailable");
                        return null;
                }
                if (account == null) {
                        reply(source, manager, "auth.admin.unknownPlayer", name);
                        return null;
                }
                return account;
        }

        /**
         * Journals a store failure with its ROOT CAUSE (since 1.2.4). Previously the
         * admin commands swallowed StoreException behind a generic "service
         * unavailable" with nothing in any log — a flaky reset was undiagnosable
         * (was it a full disk? a locked file? a broken connection?). Now the exact
         * cause (e.g. {@code SQLiteException: database disk is full}) lands in the
         * security log AND the server log, while the player-facing message stays
         * generic on purpose.
         */
        private static void logStoreFailure(CommandSourceStack source, AuthManager manager, String operation,
                        StoreException e) {
                manager.logger().log(SecurityEvent.DATABASE_UNAVAILABLE, actorName(source), null, actorIp(source),
                                operation + ":" + net.secureauth.account.StoreException.describe(e));
        }

        /** Finds an online player by name, case-insensitively; {@code null} when offline. */
        private static ServerPlayer findOnline(CommandSourceStack source, String name) {
                String norm = AccountRepository.normalize(name);
                for (ServerPlayer online : source.getServer().getPlayerList().getPlayers()) {
                        if (AccountRepository.normalize(online.getGameProfile().name()).equals(norm)) {
                                return online;
                        }
                }
                return null;
        }

        private static String actorName(CommandSourceStack source) {
                try {
                        return source.getTextName();
                } catch (RuntimeException e) {
                        return "unknown";
                }
        }

        /** IP of the command source, or {@code null} for the console (blank fields are skipped by the logger). */
        private static String actorIp(CommandSourceStack source) {
                ServerPlayer player = source.getPlayer();
                if (player == null) {
                        return null;
                }
                try {
                        return player.getIpAddress();
                } catch (RuntimeException e) {
                        return null;
                }
        }

        // ------------------------------------------------------------------
        // /auth reload support
        // ------------------------------------------------------------------

        /**
         * Copies every field of every section from the freshly loaded config into
         * the live instance, so runtime services that hold the live config object
         * see the new values immediately. Services that captured values when they
         * were constructed (rate limiter capacities, hash parameters of already
         * stored passwords, the database path) only pick changes up after a
         * restart — the reload success message says so.
         */
        private static void copyInto(AuthConfig live, AuthConfig fresh) {
                live.authentication.enabled = fresh.authentication.enabled;
                live.authentication.timeoutSeconds = fresh.authentication.timeoutSeconds;
                live.authentication.autoLoginAfterRegister = fresh.authentication.autoLoginAfterRegister;
                live.authentication.warningIntervalSeconds = fresh.authentication.warningIntervalSeconds;
                live.authentication.sessionPersistSeconds = fresh.authentication.sessionPersistSeconds;
                live.authentication.sessionRequireSameIp = fresh.authentication.sessionRequireSameIp;

                live.password.algorithm = fresh.password.algorithm;
                live.password.minimumLength = fresh.password.minimumLength;
                live.password.maximumLength = fresh.password.maximumLength;
                live.password.argon2.memoryKiB = fresh.password.argon2.memoryKiB;
                live.password.argon2.iterations = fresh.password.argon2.iterations;
                live.password.argon2.parallelism = fresh.password.argon2.parallelism;
                live.password.argon2.outputLength = fresh.password.argon2.outputLength;
                live.password.argon2.saltLength = fresh.password.argon2.saltLength;
                live.password.pbkdf2.iterations = fresh.password.pbkdf2.iterations;
                live.password.pbkdf2.outputLength = fresh.password.pbkdf2.outputLength;
                live.password.pbkdf2.saltLength = fresh.password.pbkdf2.saltLength;

                live.security.maxLoginAttempts = fresh.security.maxLoginAttempts;
                live.security.lockoutSeconds = fresh.security.lockoutSeconds;
                live.security.kickAfterFailures = fresh.security.kickAfterFailures;
                live.security.perSessionCooldownMs = fresh.security.perSessionCooldownMs;
                live.security.ipRateLimit = fresh.security.ipRateLimit;
                live.security.ipAuthAttemptsPerMinute = fresh.security.ipAuthAttemptsPerMinute;
                live.security.ipJoinAttemptsPerMinute = fresh.security.ipJoinAttemptsPerMinute;
                live.security.permanentLockAfterRepeatedLockouts = fresh.security.permanentLockAfterRepeatedLockouts;
                live.security.lockoutsForPermanentLock = fresh.security.lockoutsForPermanentLock;
                live.security.lockoutCountWindowSeconds = fresh.security.lockoutCountWindowSeconds;

                live.worldProtection.isolationMode = fresh.worldProtection.isolationMode;
                live.worldProtection.platformBlock = fresh.worldProtection.platformBlock;
                live.worldProtection.platformRadius = fresh.worldProtection.platformRadius;
                live.worldProtection.platformY = fresh.worldProtection.platformY;
                live.worldProtection.platformBox = fresh.worldProtection.platformBox;
                live.worldProtection.releaseWatchdogSeconds = fresh.worldProtection.releaseWatchdogSeconds;
                live.worldProtection.noDamageInSandbox = fresh.worldProtection.noDamageInSandbox;
                live.worldProtection.maxDriftBlocks = fresh.worldProtection.maxDriftBlocks;
                live.worldProtection.movementCorrection = fresh.worldProtection.movementCorrection;
                live.worldProtection.clearAuthEntities = fresh.worldProtection.clearAuthEntities;
                live.worldProtection.pureVoid = fresh.worldProtection.pureVoid;
                live.worldProtection.quarantineBlindness = fresh.worldProtection.quarantineBlindness;
                live.worldProtection.resetOnRestart = fresh.worldProtection.resetOnRestart;
                // The ServerLevelMixin entity-birth guard reads a static flag: keep it in sync.
                AuthWorldManager.setEntityGuard(live.worldProtection.clearAuthEntities);
                live.worldProtection.blockInteraction = fresh.worldProtection.blockInteraction;
                live.worldProtection.blockChat = fresh.worldProtection.blockChat;
                live.worldProtection.blockCommands = fresh.worldProtection.blockCommands;

                live.worldInfo.hideTabList = fresh.worldInfo.hideTabList;
                live.worldInfo.suppressChatBroadcasts = fresh.worldInfo.suppressChatBroadcasts;
                live.worldInfo.hideMaps = fresh.worldInfo.hideMaps;
                live.worldInfo.minimalCommandTree = fresh.worldInfo.minimalCommandTree;
                live.worldInfo.filterScoreboard = fresh.worldInfo.filterScoreboard;
                live.worldInfo.filterCustomPayloads = fresh.worldInfo.filterCustomPayloads;

                live.ui.actionBarTimer = fresh.ui.actionBarTimer;
                live.ui.autoOpenAuthPanel = fresh.ui.autoOpenAuthPanel;
                live.ui.adminPanel = fresh.ui.adminPanel;

                live.storage.databasePath = fresh.storage.databasePath;

                live.identity.strictUuidBinding = fresh.identity.strictUuidBinding;

                live.administration.adminOpLevel = fresh.administration.adminOpLevel;

                live.logging.authenticationEvents = fresh.logging.authenticationEvents;
                live.logging.logToFile = fresh.logging.logToFile;
                live.logging.logDir = fresh.logging.logDir;
                live.logging.maxFileBytes = fresh.logging.maxFileBytes;
                live.logging.maxFiles = fresh.logging.maxFiles;
                live.logging.logToDatabase = fresh.logging.logToDatabase;
        }
}
