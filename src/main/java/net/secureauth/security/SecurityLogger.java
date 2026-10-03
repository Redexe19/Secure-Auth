package net.secureauth.security;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import net.secureauth.account.AccountDatabase;
import net.secureauth.config.AuthConfig;

/**
 * Authentication security log.
 *
 * <p>Two sinks (both optional):</p>
 * <ol>
 *   <li>A rolling file under {@code logs/secureauth/} with size-based rotation.</li>
 *   <li>The {@code security_events} table of the account database.</li>
 * </ol>
 *
 * <p>Events are structured — actor, target, ip, details — and passed through
 * {@link Redactor} as defence in depth. Passwords, hashes and session tokens
 * must never be given to this logger.</p>
 */
public final class SecurityLogger {

	private final AuthConfig config;
	private final AccountDatabase database;
	private final Object fileLock = new Object();
	private BufferedWriter writer;
	private Path currentFile;
	private final Deque<Path> rotatedFiles = new ArrayDeque<>();

	public SecurityLogger(AuthConfig config, AccountDatabase database) {
		this.config = config;
		this.database = database;
	}

	public void log(SecurityEvent event, String actor, String target, String ip, String details) {
		if (!config.logging.authenticationEvents) {
			return;
		}
		String line = format(event, actor, target, ip, details);
		writeDatabase(event, actor, target, ip, details);
		writeFile(line);
	}

	public void log(SecurityEvent event, String actor, String target, String ip) {
		log(event, actor, target, ip, "");
	}

	public void log(SecurityEvent event, String actor, String ip) {
		log(event, actor, null, ip, "");
	}

	private String format(SecurityEvent event, String actor, String target, String ip, String details) {
		StringBuilder sb = new StringBuilder(160);
		sb.append(Instant.now().toString()).append(" | ").append(event.name());
		if (notBlank(actor)) sb.append(" | actor=").append(Redactor.scrub(actor));
		if (notBlank(target)) sb.append(" | target=").append(Redactor.scrub(target));
		if (notBlank(ip)) sb.append(" | ip=").append(ip);
		if (notBlank(details)) sb.append(" | ").append(Redactor.scrub(details));
		return sb.toString();
	}

	// ------------------------------------------------------------------
	// Database sink
	// ------------------------------------------------------------------

	private void writeDatabase(SecurityEvent event, String actor, String target, String ip, String details) {
		if (!config.logging.logToDatabase || database == null) {
			return;
		}
		try {
			database.transactional(conn -> {
				try (PreparedStatement ps = conn.prepareStatement(
						"INSERT INTO security_events (event_type, actor, target, ip, details, timestamp) VALUES (?,?,?,?,?,?)")) {
					ps.setString(1, event.name());
					ps.setString(2, truncate(actor));
					ps.setString(3, truncate(target));
					ps.setString(4, truncate(ip));
					ps.setString(5, truncate(Redactor.scrub(details)));
					ps.setTimestamp(6, new Timestamp(System.currentTimeMillis()));
					ps.executeUpdate();
				} catch (SQLException e) {
					throw new net.secureauth.account.StoreException("Failed to persist security event", e);
				}
			});
		} catch (RuntimeException e) {
			// The database sink must never take the auth system down;
			// failing closed is handled by the callers of the repository.
			System.err.println("[SecureAuth] security_events write failed: " + e.getMessage());
		}
	}

	// ------------------------------------------------------------------
	// File sink with rotation
	// ------------------------------------------------------------------

	private void writeFile(String line) {
		if (!config.logging.logToFile) {
			return;
		}
		synchronized (fileLock) {
			try {
				ensureWriter();
				writer.write(line);
				writer.newLine();
				writer.flush();
				rotateIfNeeded();
			} catch (IOException e) {
				System.err.println("[SecureAuth] security log write failed: " + e.getMessage());
				writer = null;
			}
		}
	}

	private void ensureWriter() throws IOException {
		if (writer != null) {
			return;
		}
		Path dir = Path.of(config.logging.logDir);
		Files.createDirectories(dir);
		currentFile = dir.resolve("security.log");
		// Continue appending to an existing file; it will rotate on size.
		writer = Files.newBufferedWriter(currentFile, StandardCharsets.UTF_8,
				java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
	}

	private void rotateIfNeeded() throws IOException {
		if (currentFile == null || Files.size(currentFile) < config.logging.maxFileBytes) {
			return;
		}
		writer.flush();
		writer.close();
		writer = null;
		Path rotated = currentFile.resolveSibling(
				"security-" + System.currentTimeMillis() + ".log");
		Files.move(currentFile, rotated, StandardCopyOption.REPLACE_EXISTING);
		rotatedFiles.addLast(rotated);
		while (rotatedFiles.size() > config.logging.maxFiles) {
			Path oldest = rotatedFiles.pollFirst();
			if (oldest != null) {
				Files.deleteIfExists(oldest);
			}
		}
	}

	public void close() {
		synchronized (fileLock) {
			if (writer != null) {
				try {
					writer.flush();
					writer.close();
				} catch (IOException ignored) {
				} finally {
					writer = null;
				}
			}
		}
	}

	private static boolean notBlank(String s) {
		return s != null && !s.isBlank();
	}

	private static String truncate(String s) {
		if (s == null) {
			return null;
		}
		return s.length() > 512 ? s.substring(0, 512) : s;
	}
}
