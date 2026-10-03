package net.secureauth.auth;

import net.secureauth.account.Account;
import net.secureauth.account.AccountRepository;
import net.secureauth.account.StoreException;
import net.secureauth.config.AuthConfig;
import net.secureauth.security.SecurityEvent;
import net.secureauth.security.SecurityLogger;

/**
 * Registration flow: validates the password policy, enforces "new accounts
 * only", stores the Argon2id hash and (optionally) authenticates immediately.
 */
public final class RegistrationService {

	public enum Result {
		OK,
		OK_NO_AUTO_LOGIN,
		MISMATCH,
		TOO_SHORT,
		TOO_LONG,
		ALREADY_EXISTS,
		NOT_ELIGIBLE,
		STORAGE_ERROR
	}

	private final AuthConfig config;
	private final AccountRepository repository;
	private final PasswordService passwords;
	private final SecurityLogger logger;
	private final PasswordPolicy policy;

	public RegistrationService(AuthConfig config, AccountRepository repository,
			PasswordService passwords, SecurityLogger logger) {
		this.config = config;
		this.repository = repository;
		this.passwords = passwords;
		this.logger = logger;
		this.policy = new PasswordPolicy(config.password);
	}

	/**
	 * Registers the account for {@code session}. On success the session account
	 * is attached; the caller decides whether to run the post-registration
	 * authentication immediately.
	 */
	public Result register(AuthSession session, String password, String confirmation) {
		if (password == null || confirmation == null) {
			return Result.MISMATCH;
		}
		if (!password.equals(confirmation)) {
			return Result.MISMATCH;
		}
		PasswordPolicy.Result policyResult = policy.validate(password);
		switch (policyResult) {
			case TOO_SHORT -> {
				return Result.TOO_SHORT;
			}
			case TOO_LONG -> {
				return Result.TOO_LONG;
			}
			default -> {
			}
		}
		if (session.account != null || repository.exists(session.usernameNorm)) {
			logger.log(SecurityEvent.REGISTRATION_REJECTED, session.usernameNorm, session.ip, "already_exists");
			return Result.ALREADY_EXISTS;
		}

		try {
			PasswordService.PasswordHash hash = passwords.hash(password);
			Account account = repository.create(session.usernameDisplay, offlineUuid(session), hash);
			session.account = account;
			session.state = AuthState.REGISTERING;
			logger.log(SecurityEvent.ACCOUNT_REGISTERED, session.usernameNorm, session.ip,
					"algorithm=" + hash.algorithm());
			repository.recordAttempt(account.id(), session.usernameNorm, session.ip, true, "register");
			return config.authentication.autoLoginAfterRegister ? Result.OK : Result.OK_NO_AUTO_LOGIN;
		} catch (IllegalArgumentException e) {
			if ("ACCOUNT_EXISTS".equals(e.getMessage())) {
				return Result.ALREADY_EXISTS;
			}
			return Result.STORAGE_ERROR;
		} catch (StoreException e) {
			logger.log(SecurityEvent.DATABASE_UNAVAILABLE, session.usernameNorm, session.ip, "register");
			return Result.STORAGE_ERROR;
		}
	}

	private String offlineUuid(AuthSession session) {
		try {
			return session.player.getUUID().toString();
		} catch (RuntimeException e) {
			return null;
		}
	}
}
