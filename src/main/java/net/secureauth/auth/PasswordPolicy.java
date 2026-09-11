package net.secureauth.auth;

import net.secureauth.config.AuthConfig;

/**
 * Password composition policy. Deliberately minimal: length bounds only.
 * Complicated composition rules hurt security more than they help.
 */
public final class PasswordPolicy {

	public enum Result { OK, TOO_SHORT, TOO_LONG }

	private final int minLength;
	private final int maxLength;

	public PasswordPolicy(AuthConfig.PasswordSection config) {
		this.minLength = config.minimumLength;
		this.maxLength = config.maximumLength;
	}

	public Result validate(String password) {
		if (password == null) {
			return Result.TOO_SHORT;
		}
		int length = password.length();
		if (length < minLength) {
			return Result.TOO_SHORT;
		}
		if (length > maxLength) {
			return Result.TOO_LONG;
		}
		return Result.OK;
	}

	public int minLength() {
		return minLength;
	}

	public int maxLength() {
		return maxLength;
	}
}
