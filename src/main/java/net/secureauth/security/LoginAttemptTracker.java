package net.secureauth.security;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Per-connection (per-session) attempt tracking: enforces a cooldown between
 * login attempts and counts failures within the current connection.
 * Per-account failure counters are persisted by the repository; this class is
 * purely an in-memory fast path against packet spam.
 */
public final class LoginAttemptTracker {

	public static final class AttemptState {
		int sessionFailures;
		long lastAttemptAt;
		long cooldownUntil;
	}

	private final long cooldownMillis;
	private final Map<UUID, AttemptState> sessions = new ConcurrentHashMap<>();

	public LoginAttemptTracker(long cooldownMillis) {
		this.cooldownMillis = Math.max(0, cooldownMillis);
	}

	/**
	 * Registers an attempt for the connection. Returns true when the attempt is
	 * allowed (cooldown expired); false when the caller must wait.
	 */
	public boolean tryBeginAttempt(UUID playerId) {
		AttemptState state = sessions.computeIfAbsent(playerId, k -> new AttemptState());
		synchronized (state) {
			long now = System.currentTimeMillis();
			if (now < state.cooldownUntil) {
				return false;
			}
			state.lastAttemptAt = now;
			state.cooldownUntil = now + cooldownMillis;
			return true;
		}
	}

	/** Seconds remaining until the next attempt is permitted. */
	public int cooldownRemainingSeconds(UUID playerId) {
		AttemptState state = sessions.get(playerId);
		if (state == null) {
			return 0;
		}
		synchronized (state) {
			long remaining = state.cooldownUntil - System.currentTimeMillis();
			return remaining <= 0 ? 0 : (int) Math.ceil(remaining / 1000.0);
		}
	}

	public void recordFailure(UUID playerId) {
		AttemptState state = sessions.computeIfAbsent(playerId, k -> new AttemptState());
		synchronized (state) {
			state.sessionFailures++;
		}
	}

	public int sessionFailures(UUID playerId) {
		AttemptState state = sessions.get(playerId);
		if (state == null) {
			return 0;
		}
		synchronized (state) {
			return state.sessionFailures;
		}
	}

	/** Clears state when the connection ends or authentication succeeds. */
	public void clear(UUID playerId) {
		sessions.remove(playerId);
	}
}
