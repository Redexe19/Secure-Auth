package net.secureauth.auth;

import net.minecraft.core.BlockPos;
import net.minecraft.server.level.ServerLevel;
import net.minecraft.server.level.ServerPlayer;
import net.minecraft.world.level.GameType;
import net.secureauth.account.Account;
import net.secureauth.ui.AuthPanel;
import net.secureauth.world.OriginalLocation;

/**
 * Per-connection authentication session. Created when a player joins, removed
 * when they disconnect. Everything here is authoritative server-side state.
 */
public final class AuthSession {

        /**
         * The player this session belongs to. NOT final: a cross-dimension
         * teleport recreates the {@code ServerPlayer} entity (the connection's
         * player reference is swapped, the old entity is discarded), so the
         * tick loop re-binds this field to the live entity whenever it changes
         * (since 1.2.4 — without it the release watchdog kept "rescuing" a
         * discarded entity whose teleport silently no-ops while the real
         * player stayed stuck in the auth dimension).
         */
        public ServerPlayer player;
        public final String usernameNorm;
        public final String usernameDisplay;
        public final String ip;

        public AuthState state = AuthState.UNREGISTERED;
        public Account account;

        /** Snapshot taken before the player was moved into the auth area. */
        public OriginalLocation originalLocation;

        /** Where the player is held inside the auth area. */
        public ServerLevel authLevel;
        public BlockPos authSpawn;

        public final long joinedAt = System.currentTimeMillis();
        public long deadline;
        public long lastTimeoutWarningAt;
        public long lastBlockedNoticeAt;
        public long lastFeedbackAt;

        /**
         * When this session last became authenticated (0 = never). Read by the
         * release watchdog: an authenticated player who is STILL inside the auth
         * dimension this many seconds later is automatically rescued.
         */
        public long authAtMs;
        /**
         * True once the ability reconciliation has confirmed (or repaired) this
         * session's state while the player is OUTSIDE the auth dimension. One-shot
         * per quarantine: every {@code quarantine()} re-arms it, and the first
         * one-second pass after the player leaves the sandbox settles it — the
         * reconciliation must never run again afterwards, or it would fight later
         * operator game-mode/effect changes on a fully released player.
         */
        public boolean abilitiesReconciled;
        /**
         * The AUTH-TIME game type of this session (the post-restore value), or
         * {@code null}. Set at every auth success and inherited from the resume
         * record on a trusted rejoin. The ability reconciliation uses it as the
         * game-type source for resumed sessions, which carry no quarantine
         * snapshot — and it is what gets written into the resume record at
         * disconnect (never the live value, which a missed restore could have
         * left poisoned at the sandbox's adventure).
         */
        public GameType resumedGameMode;
        /** Throttle for the release-watchdog "you were sent back" notice (max 1 per 5 s). */
        public long lastRescueNoticeAt;
        /** Throttle for the release-watchdog security log entries (max 1 per 5 s). */
        public long lastRescueLogAt;

        /** The auth chest panel this player currently has open, if any. */
        public AuthPanel openPanel;

        AuthSession(ServerPlayer player, String usernameNorm, String usernameDisplay, String ip) {
                this.player = player;
                this.usernameNorm = usernameNorm;
                this.usernameDisplay = usernameDisplay;
                this.ip = ip;
        }

        /** Auth screen data: how many tries the account has left (server-authoritative). */
        public int attemptsRemaining(int maxAttempts) {
                if (account == null) {
                        return maxAttempts;
                }
                return Math.max(0, maxAttempts - account.failedAttempts());
        }

        public boolean authenticated() {
                return state == AuthState.AUTHENTICATED;
        }

        public long secondsUntilDeadline() {
                return Math.max(0, (deadline - System.currentTimeMillis() + 999) / 1000);
        }
}
