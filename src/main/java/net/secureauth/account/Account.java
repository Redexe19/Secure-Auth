package net.secureauth.account;

import java.time.Instant;

/**
 * A persistent authentication account.
 *
 * <p>Identity model for offline-mode servers: the canonical key is the
 * <em>normalized (lowercase) username</em>; the offline UUID captured at
 * registration is stored for optional strict binding. Password material is
 * kept as algorithm + version + salt + hash + parameters, never plaintext.</p>
 */
public final class Account {

	private long id;
	private final String usernameNorm;
	private final String usernameDisplay;
	private final String offlineUuid;

	private final String algorithm;
	private final int hashVersion;
	private final byte[] salt;
	private final byte[] hash;
	private final String hashParams;

	private final long createdAt;
	private Long lastLogin;
	private int failedAttempts;
	private long lockoutUntil;
	private boolean locked;

	public Account(long id, String usernameNorm, String usernameDisplay, String offlineUuid,
			String algorithm, int hashVersion, byte[] salt, byte[] hash, String hashParams,
			long createdAt, Long lastLogin, int failedAttempts, long lockoutUntil, boolean locked) {
		this.id = id;
		this.usernameNorm = usernameNorm;
		this.usernameDisplay = usernameDisplay;
		this.offlineUuid = offlineUuid;
		this.algorithm = algorithm;
		this.hashVersion = hashVersion;
		this.salt = salt;
		this.hash = hash;
		this.hashParams = hashParams;
		this.createdAt = createdAt;
		this.lastLogin = lastLogin;
		this.failedAttempts = failedAttempts;
		this.lockoutUntil = lockoutUntil;
		this.locked = locked;
	}

	// --- Identity -------------------------------------------------------

	/** Normalized (lowercase) username — the unique account key. */
	public String usernameNorm() {
		return usernameNorm;
	}

	/** Display-cased name as first registered. */
	public String usernameDisplay() {
		return usernameDisplay;
	}

	/** Offline-mode UUID captured at registration (may be null). */
	public String offlineUuid() {
		return offlineUuid;
	}

	public long id() {
		return id;
	}

	public void assignId(long id) {
		this.id = id;
	}

	// --- Password material (never logged) --------------------------------

	public String algorithm() {
		return algorithm;
	}

	public int hashVersion() {
		return hashVersion;
	}

	public byte[] salt() {
		return salt;
	}

	public byte[] hash() {
		return hash;
	}

	public String hashParams() {
		return hashParams;
	}

	// --- Bookkeeping -----------------------------------------------------

	public long createdAt() {
		return createdAt;
	}

	public Long lastLogin() {
		return lastLogin;
	}

	public void setLastLogin(long epochMillis) {
		this.lastLogin = epochMillis;
	}

	public int failedAttempts() {
		return failedAttempts;
	}

	public void setFailedAttempts(int failedAttempts) {
		this.failedAttempts = failedAttempts;
	}

	public long lockoutUntil() {
		return lockoutUntil;
	}

	public void setLockoutUntil(long epochMillis) {
		this.lockoutUntil = epochMillis;
	}

	public boolean locked() {
		return locked;
	}

	public void setLocked(boolean locked) {
		this.locked = locked;
	}

	/** True while a temporary lockout is active. */
	public boolean inTemporaryLockout(long now) {
		return !locked && lockoutUntil > now;
	}

	/** Formatted registration time for safe display. */
	public String registeredAtIso() {
		return Instant.ofEpochMilli(createdAt).toString();
	}

	/** Formatted last login for safe display (metadata only). */
	public String lastLoginIso() {
		return lastLogin == null ? "never" : Instant.ofEpochMilli(lastLogin).toString();
	}
}
