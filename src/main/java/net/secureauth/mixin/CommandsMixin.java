package net.secureauth.mixin;

import com.mojang.brigadier.ParseResults;
import java.util.Locale;
import net.minecraft.commands.CommandSourceStack;
import net.minecraft.commands.Commands;
import net.minecraft.server.level.ServerPlayer;
import net.secureauth.SecureAuth;
import net.secureauth.auth.AuthManager;
import net.secureauth.auth.AuthSession;
import net.secureauth.config.AuthConfig;
import net.secureauth.security.Redactor;
import net.secureauth.security.SecurityEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Unique;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

/**
 * Pre-authentication command gate (fail closed).
 *
 * <p><b>Verified 26.2 command funnel</b> (minijavap + {@code javap -c} on the
 * real game-server jar): every player chat command — signed
 * ({@code ServerboundChatCommandSignedPacket}) and unsigned
 * ({@code ServerboundChatCommandPacket}) — is executed through
 * {@code ServerGamePacketListenerImpl.performUnsignedChatCommand} /
 * {@code performSignedChatCommand}, both of which call
 * {@link Commands#performCommand(ParseResults, String)} directly. Command
 * blocks and minecart command blocks call it too, and
 * {@link Commands#performPrefixedCommand(CommandSourceStack, String)} — used
 * by the dedicated-server console and RCON — delegates to
 * {@code performCommand} after trimming the optional {@code '/'} prefix.
 * Both entry points are therefore injected here:
 * {@code performCommand} is the effective gate for players, and the
 * {@code performPrefixedCommand} injection covers the contract and any
 * future caller of the prefixed API directly (non-player sources pass the
 * player check immediately). Both methods are public, return {@code void}
 * and use the descriptors
 * {@code performPrefixedCommand(Lnet/minecraft/commands/CommandSourceStack;Ljava/lang/String;)V}
 * and {@code performCommand(Lcom/mojang/brigadier/ParseResults;Ljava/lang/String;)V};
 * cancellation is a plain {@code ci.cancel()}.</p>
 *
 * <p><b>What it blocks.</b> While the executing source resolves to a player
 * whose session is unauthenticated — <em>including a missing session</em>
 * (fail closed: the contract says {@code session() == null} means the player
 * never passed through our join handler, which is exactly the state an
 * attacker wants) — only the six SecureAuth command roots may run:
 * {@code register}, {@code login}, {@code logout}, {@code changepassword},
 * {@code unregister} and {@code auth}. Anything else — including
 * namespace-qualified roots such as {@code minecraft:tp} and unknown
 * commands — is cancelled before brigadier ever parses it. Console, RCON,
 * command block, function and other player-less sources always pass: they
 * are outside the authentication sandbox. The gate honours the
 * {@code worldProtection.blockCommands} configuration switch.</p>
 *
 * <p><b>Feedback and logging.</b> Blocked players get the branded, translated
 * {@code auth.command.blocked} message (via
 * {@link AuthManager#sendTranslated(ServerPlayer, String, Object...)}, which
 * wraps the send in {@code PacketBypass} so the outgoing filter cannot drop
 * it), throttled to one notice per 3 seconds per session through
 * {@code AuthSession.lastBlockedNoticeAt}. A
 * {@code SecurityEvent.COMMAND_BLOCKED} entry is written with the scrubbed
 * command text, throttled to at most one entry per 5 seconds via a
 * {@code @Unique} static timestamp (a global floor on log volume, merging
 * bursts from different players — the per-session chat notice already bounds
 * player-visible spam). The command text is truncated to 120 characters and
 * passed through {@link Redactor#scrub(String)}; the security logger scrubs
 * again, so accidental {@code password=...} fragments can never reach the
 * log. The 5-argument {@code SecurityLogger.log} overload is used explicitly
 * ({@code (event, actor, target, ip, details)}) because the 4-argument
 * overload is {@code (event, actor, target, ip)} — passing
 * {@code (actor, ip, details)} would silently put the command text into the
 * {@code ip} column.</p>
 *
 * <p><b>Failure policy.</b> The gate never throws: mod disabled/absent,
 * manager absent, blank command strings and player-less sources pass through
 * unchanged, and any unexpected internal error fails <em>closed</em> (the
 * command is cancelled) with a debug log — the auth commands themselves are
 * plain string matching and cannot be affected by such an error.</p>
 */
@Mixin(Commands.class)
public abstract class CommandsMixin {

        /** Debug-only logger for unexpected internal states (never the security log). */
        @Unique
        private static final Logger SECUREAUTH_LOG = LoggerFactory.getLogger("secureauth.mixin");

        /** The only command roots reachable before authentication (no aliases). */
        @Unique
        private static final String[] SECUREAUTH_ALLOWED_ROOTS = {
                        "register", "login", "logout", "changepassword", "unregister", "auth", "authpanel"
        };

        /** Minimum interval between two "command blocked" chat notices (per session). */
        @Unique
        private static final long SECUREAUTH_NOTICE_INTERVAL_MS = 3000L;

        /** Minimum interval between two COMMAND_BLOCKED log entries (global floor). */
        @Unique
        private static final long SECUREAUTH_LOG_INTERVAL_MS = 5000L;

        /** Maximum length of the logged (scrubbed) command text. */
        @Unique
        private static final int SECUREAUTH_MAX_LOG_LENGTH = 120;

        /** Timestamp of the last COMMAND_BLOCKED log entry (ms; global, benignly racy). */
        @Unique
        private static long secureauth$lastBlockedLogAt;

        @Inject(method = "performPrefixedCommand(Lnet/minecraft/commands/CommandSourceStack;Ljava/lang/String;)V",
                        at = @At("HEAD"), cancellable = true)
        private void secureauth$onPerformPrefixedCommand(CommandSourceStack source, String command, CallbackInfo ci) {
                // Console/RCON input: the raw string may carry a leading '/' (stripped below).
                secureauth$gate(source, command, ci);
        }

        @Inject(method = "performCommand(Lcom/mojang/brigadier/ParseResults;Ljava/lang/String;)V",
                        at = @At("HEAD"), cancellable = true)
        private void secureauth$onPerformCommand(ParseResults<CommandSourceStack> parseResults, String command,
                        CallbackInfo ci) {
                // The funnel for every player-executed command (chat signed/unsigned).
                CommandSourceStack source = null;
                if (parseResults != null && parseResults.getContext() != null) {
                        source = parseResults.getContext().getSource();
                }
                secureauth$gate(source, command, ci);
        }

        /**
         * Shared gate. Fail closed: a player source without a live, authenticated
         * session is blocked unless the command root is one of the six auth roots.
         * Non-player sources and a disabled/inert mod pass through. Never throws.
         */
        private void secureauth$gate(CommandSourceStack source, String command, CallbackInfo ci) {
                try {
                        if (source == null || command == null || command.isBlank()) {
                                // Nothing executable; brigadier's own behaviour is untouched.
                                return;
                        }
                        SecureAuth self = SecureAuth.get();
                        if (self == null || !self.enabled()) {
                                return;
                        }
                        AuthManager manager = self.authManager();
                        if (manager == null) {
                                return;
                        }
                        AuthConfig config = manager.config();
                        if (config == null || !config.worldProtection.blockCommands) {
                                return;
                        }
                        ServerPlayer player = source.getPlayer();
                        if (player == null) {
                                // Console, RCON, command blocks, functions, datapacks.
                                return;
                        }
                        AuthSession session = manager.session(player);
                        if (session != null && session.authenticated()) {
                                return;
                        }

                        String root = secureauth$rootToken(command);
                        if (!root.isEmpty() && secureauth$isAllowedRoot(root)) {
                                return;
                        }

                        // Blocked — fail closed (a missing session counts as unauthenticated).
                        ci.cancel();
                        secureauth$notify(manager, session, player, command);
                } catch (Throwable t) {
                        // The gate itself must never break command execution; fail closed.
                        ci.cancel();
                        SECUREAUTH_LOG.debug("SecureAuth command gate error; command blocked", t);
                }
        }

        /** Throttled player feedback + security log for a blocked command. Never throws. */
        private static void secureauth$notify(AuthManager manager, AuthSession session, ServerPlayer player,
                        String command) {
                if (session == null) {
                        // No session => no throttle state; stay silent (the block itself is enough).
                        return;
                }
                try {
                        long now = System.currentTimeMillis();
                        if (now - session.lastBlockedNoticeAt >= SECUREAUTH_NOTICE_INTERVAL_MS) {
                                session.lastBlockedNoticeAt = now;
                                manager.sendTranslated(player, "auth.command.blocked");
                        }
                        if (now - secureauth$lastBlockedLogAt >= SECUREAUTH_LOG_INTERVAL_MS) {
                                secureauth$lastBlockedLogAt = now;
                                manager.logger().log(SecurityEvent.COMMAND_BLOCKED, session.usernameNorm, null,
                                                session.ip, "command=" + secureauth$scrubbed(command));
                        }
                } catch (Throwable t) {
                        SECUREAUTH_LOG.debug("SecureAuth command-block feedback failed", t);
                }
        }

        /**
         * Strips the optional leading '/', then returns the lowercased first
         * whitespace-delimited token (the command root). Namespace-qualified
         * roots such as {@code minecraft:tp} are returned verbatim and
         * therefore never match the allow-list.
         */
        private static String secureauth$rootToken(String command) {
                String trimmed = command.trim();
                if (trimmed.startsWith("/")) {
                        trimmed = trimmed.substring(1);
                }
                int end = trimmed.length();
                for (int i = 0; i < trimmed.length(); i++) {
                        if (Character.isWhitespace(trimmed.charAt(i))) {
                                end = i;
                                break;
                        }
                }
                return trimmed.substring(0, end).toLowerCase(Locale.ROOT);
        }

        /** True when {@code root} is one of the six pre-authentication command roots. */
        private static boolean secureauth$isAllowedRoot(String root) {
                for (String allowed : SECUREAUTH_ALLOWED_ROOTS) {
                        if (allowed.equals(root)) {
                                return true;
                        }
                }
                return false;
        }

        /** Truncates and scrubs the command text for the security log. */
        private static String secureauth$scrubbed(String command) {
                String text = command.length() > SECUREAUTH_MAX_LOG_LENGTH
                                ? command.substring(0, SECUREAUTH_MAX_LOG_LENGTH)
                                : command;
                return Redactor.scrub(text);
        }
}
