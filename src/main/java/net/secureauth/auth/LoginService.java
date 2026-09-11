package net.secureauth.auth;

import net.secureauth.account.Account;
import net.secureauth.account.AccountRepository;
import net.secureauth.account.StoreException;
import net.secureauth.config.AuthConfig;
import net.secureauth.security.LoginAttemptTracker;
import net.secureauth.security.RateLimiter;
import net.secureauth.security.SecurityEvent;
import net.secureauth.security.SecurityLogger;

/**
 * Login flow with layered brute-force protection:
 * <ol>
 *   <li>per-connection cooldown (anti packet-spam),</li>
 *   <li>per-IP token-bucket rate limit,</li>
 *   <li>per-account failure counter with temporary lockout,</li>
 *   <li>session failure cap with kick.</li>
 * </ol>
 *
 * <p>Temporary lockouts are used by default so a hostile third party cannot
 * permanently lock someone else's account (denial of service); permanent locks
 * exist only as an explicit opt-in and as an administrator action.</p>
 */
public final class LoginService {

	public sealed interface Result {
		record Success(Account account) implements Result {
		}

		record Failure(String messageKey, Object arg) implements Result {
			public static Failure of(String key) {
				return new Failure(key, null);
			}

			public static Failure of(String key, Object arg) {
				return new Failure(key, arg);
			}
		}

		record StorageError() implements Result {
		}
	}

	private final AuthConfig config;
	private final AccountRepository repository;
	private final PasswordService passwords;
	private final SecurityLogger logger;
	private final RateLimiter ipAuthLimiter;
	private final LoginAttemptTracker tracker;

	public LoginService(AuthConfig config, AccountRepository repository, PasswordService passwords,
			SecurityLogger logger, RateLimiter ipAuthLimiter, LoginAttemptTracker tracker) {
		this.config = config;
		this.repository = repository;
		this.passwords = passwords;
		this.logger = logger;
		this.ipAuthLimiter = ipAuthLimiter;
		this.tracker = tracker;
	}

	/**
	 * Attempts to authenticate {@code session} with the given password.
	 * The session must belong to the same connection that sent the attempt.
	 */
	public Result attempt(AuthSession session, String password) {
		if (password == null) {
			return Result.Failure.of("auth.error.packet");
		}

		// Layer 1: per-connection cooldown.
		if (!tracker.tryBeginAttempt(session.player.getUUID())) {
			return Result.Failure.of("auth.login.cooldown",
					tracker.cooldownRemainingSeconds(session.player.getUUID()));
		}

		// Layer 2: per-IP rate limit.
		if (config.security.ipRateLimit && !ipAuthLimiter.tryAcquire(session.ip)) {
			logger.log(SecurityEvent.LOGIN_FAILURE, session.usernameNorm, session.ip, "ip_rate_limited");
			return Result.Failure.of("auth.login.rateLimited");
		}

		try {
			Account account = session.account != null
					? session.account
					: repository.findByUsernameNorm(session.usernameNorm).orElse(null);
			if (account == null) {
				// Do not confirm whether the account exists (anti-enumeration).
				repository.recordAttempt(null, session.usernameNorm, session.ip, false, "no_account");
				logger.log(SecurityEvent.LOGIN_FAILURE, session.usernameNorm, session.ip, "no_account");
				return Result.Failure.of("auth.login.notRegistered");
			}
			session.account = account;
			session.state = AuthState.REGISTERED_NOT_AUTHENTICATED;

			long now = System.currentTimeMillis();

			// Administrator-issued permanent lock.
			if (account.locked()) {
				return Result.Failure.of("auth.login.lockedPermanent");
			}

			// Layer 3: temporary account lockout.
			if (account.inTemporaryLockout(now)) {
				long seconds = (account.lockoutUntil() - now + 999) / 1000;
				return Result.Failure.of("auth.login.locked", seconds);
			}

			// The actual password verification (constant-time).
			PasswordService.PasswordHash stored = new PasswordService.PasswordHash(
					account.algorithm(), account.hashVersion(), account.salt(), account.hash(), account.hashParams());
			if (passwords.verify(stored, password)) {
				repository.recordLoginSuccess(account.id());
				repository.recordAttempt(account.id(), session.usernameNorm, session.ip, true, "login");
				account.setFailedAttempts(0);
				account.setLockoutUntil(0);
				account.setLastLogin(now);
				logger.log(SecurityEvent.LOGIN_SUCCESS, session.usernameNorm, session.ip);
				tracker.clear(session.player.getUUID());
				return new Result.Success(account);
			}

			// Failure path: count, journal, maybe lock.
			return onFailure(session, account);

		} catch (StoreException e) {
			logger.log(SecurityEvent.DATABASE_UNAVAILABLE, session.usernameNorm, session.ip, "login");
			// Fail closed: no authentication without a readable database.
			return new Result.StorageError();
		}
	}

	private Result onFailure(AuthSession session, Account account) {
		int failures = repository.recordLoginFailure(account.id());
		account.setFailedAttempts(failures);
		tracker.recordFailure(session.player.getUUID());
		repository.recordAttempt(account.id(), session.usernameNorm, session.ip, false, "wrong_password");
		logger.log(SecurityEvent.LOGIN_FAILURE, session.usernameNorm, session.ip,
				"failed_attempts=" + failures);

		int max = config.security.maxLoginAttempts;

		if (failures >= max) {
			long until = System.currentTimeMillis() + config.security.lockoutSeconds * 1000L;
			repository.setLockout(account.id(), until);
			account.setLockoutUntil(until);
			logger.log(SecurityEvent.ACCOUNT_LOCKED, session.usernameNorm, session.ip,
					"for_seconds=" + config.security.lockoutSeconds);
			// Optional (dangerous) permanent lock after repeated lockouts.
			if (config.security.permanentLockAfterRepeatedLockouts
					&& failures >= max * config.security.lockoutsForPermanentLock) {
				repository.setLocked(account.id(), true);
				account.setLocked(true);
				logger.log(SecurityEvent.ACCOUNT_PERMANENTLY_LOCKED, session.usernameNorm, session.ip);
			}
			return Result.Failure.of("auth.login.locked", config.security.lockoutSeconds);
		}

		// Layer 4: kick after excessive in-session failures.
		if (tracker.sessionFailures(session.player.getUUID()) >= config.security.kickAfterFailures) {
			return Result.Failure.of("auth.login.rateLimited");
		}

		return Result.Failure.of("auth.login.incorrect");
	}

	/** Attempts remaining for feedback messages (server-authoritative). */
	public int attemptsRemaining(AuthSession session) {
		if (session.account == null) {
			return config.security.maxLoginAttempts;
		}
		return Math.max(0, config.security.maxLoginAttempts - session.account.failedAttempts());
	}
}
