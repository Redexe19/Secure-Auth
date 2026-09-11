package net.secureauth.security;

import java.util.regex.Pattern;

/**
 * Defense-in-depth scrubber for anything that might end up in a log line.
 * The architecture never passes secrets into the logger, but this rewrites
 * accidental occurrences of credential-like key/value pairs.
 */
public final class Redactor {

	private static final Pattern SECRET_PATTERN = Pattern.compile(
			"(?i)(password|passwd|secret|token|authorization|hash)\\s*[:=]\\s*\\S+");

	private Redactor() {
	}

	/** Returns a copy of {@code input} with secret-looking values masked. */
	public static String scrub(String input) {
		if (input == null || input.isEmpty()) {
			return input;
		}
		return SECRET_PATTERN.matcher(input).replaceAll("$1=[REDACTED]");
	}
}
