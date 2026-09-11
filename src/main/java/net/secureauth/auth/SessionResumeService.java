package net.secureauth.auth;

import java.util.Iterator;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import net.minecraft.world.level.GameType;
import net.secureauth.config.AuthConfig;

/**
 * Server-side quick re-login for short reconnects (the AuthMe-style "session").
 *
 * <p>When a player disconnects while authenticated, their identity — offline UUID,
 * normalised username and IP — is remembered in memory for
 * {@code authentication.sessionPersistSeconds} (default 43200 = 12 hours, 0 = off).
 * A re-join of the same UUID from the same IP inside that window is
 * auto-authenticated without a password prompt, so short reconnects and routine
 * re-joins are not a login hassle. A join from a different IP (or after the
 * window expired) always requires the normal password login.</p>
 *
 * <p>This is the server-side-only replacement of the former client-stored session
 * tokens: no client storage, no wire token, nothing to leak from a database dump.
 * The trade-off is documented — a shared NAT IP lets anyone with the same name
 * resume the session — which is why {@code sessionRequireSameIp} is on by default,
 * why the window can be shortened or disabled per server, and why every resume is
 * written to the security log as {@code SESSION_RESUMED}.</p>
 */
public final class SessionResumeService {

        private record ResumeRecord(String usernameNorm, String ip, long expiresAt, GameType gameMode) {
        }

        private final AuthConfig config;

        private final Map<UUID, ResumeRecord> records = new ConcurrentHashMap<>();

        public SessionResumeService(AuthConfig config) {
                this.config = config;
        }

        /** True when the feature is enabled (persist window > 0). */
        public boolean enabled() {
                return config.authentication.sessionPersistSeconds > 0;
        }

        /**
         * Called when an authenticated player disconnects; remembers the identity.
         * The game type is the AUTH-TIME truth (the post-restore value), not the
         * live value at disconnect — a restore that missed the live entity would
         * otherwise record the sandbox's adventure as the truth.
         */
        public void recordAuthenticated(UUID uuid, String usernameNorm, String ip, GameType gameMode) {
                if (!enabled() || uuid == null) {
                        return;
                }
                long window = config.authentication.sessionPersistSeconds * 1000L;
                records.put(uuid, new ResumeRecord(usernameNorm, ip,
                                System.currentTimeMillis() + window, gameMode));
        }

        /** Legacy overload (no game type remembered). */
        public void recordAuthenticated(UUID uuid, String usernameNorm, String ip) {
                recordAuthenticated(uuid, usernameNorm, ip, null);
        }

        /** Kills the resume window (manual logout, password change, unregister). */
        public void invalidate(UUID uuid) {
                if (uuid != null) {
                        records.remove(uuid);
                }
        }

        /**
         * True when the joining player matches a live resume record (same UUID,
         * same username, optionally same IP). Expired entries are removed lazily.
         */
        public boolean matches(UUID uuid, String usernameNorm, String ip) {
                if (!enabled() || uuid == null) {
                        return false;
                }
                ResumeRecord record = records.get(uuid);
                if (record == null) {
                        return false;
                }
                if (System.currentTimeMillis() > record.expiresAt()) {
                        records.remove(uuid);
                        return false;
                }
                if (!record.usernameNorm().equals(usernameNorm)) {
                        return false;
                }
                return !config.authentication.sessionRequireSameIp || record.ip().equals(ip);
        }

        /** Consumes the record after a successful resume (one-shot by design). */
        public void consume(UUID uuid) {
                if (uuid != null) {
                        records.remove(uuid);
                }
        }

        /**
         * The auth-time game type remembered for a live resume record, or
         * {@code null}. Read BEFORE {@link #consume} on the resume join path —
         * the ability reconciliation uses it as the game-type source for resumed
         * sessions (which carry no quarantine snapshot).
         */
        public GameType lastGameMode(UUID uuid) {
                if (uuid == null) {
                        return null;
                }
                ResumeRecord record = records.get(uuid);
                return record != null ? record.gameMode() : null;
        }

        /** Housekeeping: drops expired records (called periodically from the tick loop). */
        public void clearExpired() {
                long now = System.currentTimeMillis();
                Iterator<ResumeRecord> it = records.values().iterator();
                while (it.hasNext()) {
                        if (now > it.next().expiresAt()) {
                                it.remove();
                        }
                }
        }
}
