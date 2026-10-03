package net.secureauth.account;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.function.Consumer;
import net.secureauth.config.AuthConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * SQLite-backed account database.
 *
 * <p>SQLite is a transactional, single-file database: far more robust than any
 * flat-file format. The schema is versioned through a {@code schema_migrations}
 * table so future versions can upgrade in place. All writes run inside
 * transactions.</p>
 *
 * <p>Since 1.2.4 the connection is self-healing: a transaction that fails on a
 * broken connection (I/O hiccup, native error, poisoned transaction state —
 * previously the cause of a persistent "authentication service unavailable"
 * that only a server restart could cure) closes and reopens the SQLite
 * connection and retries the work exactly once, and every failure is logged
 * with its full root cause so the actual reason (disk full, read-only file,
 * locked database) is visible in the server log instead of being swallowed
 * by a generic player-facing message.</p>
 */
public final class AccountDatabase implements AutoCloseable {

        private static final Logger LOG = LoggerFactory.getLogger("secureauth");

        private final Path file;
        private Connection connection;

        public AccountDatabase(AuthConfig config) {
                this.file = Path.of(config.storage.databasePath);
        }

        /** Opens the database and applies pending migrations. */
        public synchronized void open() {
                if (connection != null) {
                        return;
                }
                try {
                        Class.forName("org.sqlite.JDBC");
                } catch (ClassNotFoundException e) {
                        throw new StoreException("SQLite JDBC driver is not present on the classpath", e);
                }
                try {
                        if (file.getParent() != null) {
                                Files.createDirectories(file.getParent());
                        }
                        connection = DriverManager.getConnection("jdbc:sqlite:" + file);
                        try (Statement stmt = connection.createStatement()) {
                                stmt.execute("PRAGMA journal_mode=WAL");
                                stmt.execute("PRAGMA synchronous=NORMAL");
                                stmt.execute("PRAGMA foreign_keys=ON");
                                stmt.execute("PRAGMA busy_timeout=5000");
                        }
                        migrate();
                } catch (SQLException | java.io.IOException e) {
                        throw new StoreException("Failed to open account database at " + file, e);
                }
        }

        /**
         * Runs {@code work} inside a transaction; rolls back on any exception.
         *
         * <p>Self-healing (since 1.2.4): when a transaction fails, the connection is
         * closed, reopened (SQLite recovers WAL state on open) and the work is retried
         * exactly once. This cures the two real-world failure classes behind the
         * persistent "service unavailable" on {@code /auth reset}: a connection left
         * in a broken transaction/auto-commit state by an earlier error, and transient
         * SQLITE_BUSY/IOERR hiccups (e.g. an external backup tool touching the file).
         * A genuinely persistent error (disk full, read-only file) still fails closed —
         * but now it is logged with its exact SQLite cause.</p>
         */
        public synchronized void transactional(Consumer<Connection> work) {
                ensureOpen();
                RuntimeException failure = runTransaction(work);
                if (failure == null) {
                        return;
                }
                // Heal and retry once: a fresh connection is the cure for a broken
                // transaction state; harmless for genuinely failing SQL.
                LOG.warn("[SecureAuth] account store transaction failed ({}); reopening the connection and retrying once",
                                StoreException.describe(failure));
                healConnection("transaction failure");
                RuntimeException second = runTransaction(work);
                if (second == null) {
                        LOG.warn("[SecureAuth] account store recovered after a self-heal retry");
                        return;
                }
                LOG.error("[SecureAuth] account store transaction failed permanently: {} - "
                                + "authentication fails closed until this is fixed (check disk space, "
                                + "file permissions and external locks on the database file)",
                                StoreException.describe(second), second);
                throw second;
        }

        /** One transaction attempt; {@code null} on success, the failure otherwise. */
        private RuntimeException runTransaction(Consumer<Connection> work) {
                ensureOpen();
                boolean oldAutoCommit = true;
                try {
                        oldAutoCommit = connection.getAutoCommit();
                        connection.setAutoCommit(false);
                        work.accept(connection);
                        connection.commit();
                        return null;
                } catch (Exception e) {
                        try {
                                connection.rollback();
                        } catch (SQLException suppressed) {
                                e.addSuppressed(suppressed);
                        }
                        return (e instanceof StoreException se) ? se : new StoreException("Transaction failed", e);
                } finally {
                        try {
                                connection.setAutoCommit(oldAutoCommit);
                        } catch (SQLException broken) {
                                // The connection is now in an unknown state: force the self-heal
                                // path so the next transaction starts from a fresh connection.
                                LOG.warn("[SecureAuth] account store connection could not reset auto-commit; "
                                                + "it will be reopened on the next transaction ({})", broken.getMessage());
                                connection = null;
                        }
                }
        }

        /** Closes and reopens the SQLite connection (fresh WAL state, fresh transaction state). */
        private void healConnection(String reason) {
                if (connection != null) {
                        try {
                                connection.close();
                        } catch (SQLException ignored) {
                                // Already broken — that is why we are here.
                        } finally {
                                connection = null;
                        }
                }
                LOG.warn("[SecureAuth] account store connection reopened after {}", reason);
                open();
        }

        /** Raw connection for repository reads (single writer thread: the server thread). */
        public synchronized Connection connection() {
                ensureOpen();
                return connection;
        }

        public synchronized boolean healthy() {
                try {
                        ensureOpen();
                        try (Statement stmt = connection.createStatement(); ResultSet rs = stmt.executeQuery("SELECT 1")) {
                                return rs.next();
                        }
                } catch (SQLException | RuntimeException e) {
                        return false;
                }
        }

        /**
         * Periodic health probe (once per 30 s from the server tick): reopens the
         * connection when the probe fails, so a store that broke silently heals
         * itself instead of failing every command until the next restart.
         */
        public synchronized void selfCheck() {
                if (connection == null || !healthy()) {
                        healConnection("self-check probe failure");
                        LOG.warn("[SecureAuth] account store self-check: connection healed; healthy={}", healthy());
                }
        }

        @Override
        public synchronized void close() {
                if (connection != null) {
                        try {
                                connection.close();
                        } catch (SQLException ignored) {
                        } finally {
                                connection = null;
                        }
                }
        }

        // ------------------------------------------------------------------
        // Migrations
        // ------------------------------------------------------------------

        private void migrate() throws SQLException {
                try (Statement stmt = connection.createStatement()) {
                        stmt.execute("""
                                        CREATE TABLE IF NOT EXISTS schema_migrations (
                                                version INTEGER PRIMARY KEY,
                                                applied_at INTEGER NOT NULL
                                        )""");
                }
                int current = currentVersion();
                if (current < 1) {
                        applyMigration(1, """
                                        CREATE TABLE accounts (
                                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                                username_norm TEXT NOT NULL UNIQUE,
                                                username_display TEXT NOT NULL,
                                                uuid_offline TEXT,
                                                algorithm TEXT NOT NULL,
                                                hash_version INTEGER NOT NULL,
                                                salt BLOB NOT NULL,
                                                hash BLOB NOT NULL,
                                                hash_params TEXT NOT NULL,
                                                created_at INTEGER NOT NULL,
                                                last_login INTEGER,
                                                failed_attempts INTEGER NOT NULL DEFAULT 0,
                                                lockout_until INTEGER NOT NULL DEFAULT 0,
                                                locked INTEGER NOT NULL DEFAULT 0
                                        );
                                        CREATE INDEX idx_accounts_uuid ON accounts(uuid_offline);
                                        CREATE TABLE login_attempts (
                                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                                account_id INTEGER,
                                                username TEXT,
                                                ip TEXT,
                                                success INTEGER NOT NULL,
                                                reason TEXT,
                                                timestamp INTEGER NOT NULL
                                        );
                                        CREATE INDEX idx_attempts_account ON login_attempts(account_id, timestamp);
                                        CREATE INDEX idx_attempts_ip ON login_attempts(ip, timestamp);
                                        CREATE TABLE security_events (
                                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                                event_type TEXT NOT NULL,
                                                actor TEXT,
                                                target TEXT,
                                                ip TEXT,
                                                details TEXT,
                                                timestamp INTEGER NOT NULL
                                        );
                                        CREATE INDEX idx_events_type ON security_events(event_type, timestamp);
                                        """);
                }
        }

        private int currentVersion() throws SQLException {
                try (Statement stmt = connection.createStatement();
                                ResultSet rs = stmt.executeQuery("SELECT COALESCE(MAX(version), 0) FROM schema_migrations")) {
                        return rs.next() ? rs.getInt(1) : 0;
                }
        }

        private void applyMigration(int version, String sql) throws SQLException {
                connection.setAutoCommit(false);
                try (Statement stmt = connection.createStatement()) {
                        for (String statement : sql.split(";")) {
                                String trimmed = statement.trim();
                                if (!trimmed.isEmpty()) {
                                        stmt.execute(trimmed);
                                }
                        }
                        try (PreparedStatement insert = connection.prepareStatement(
                                        "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)")) {
                                insert.setInt(1, version);
                                insert.setLong(2, System.currentTimeMillis());
                                insert.executeUpdate();
                        }
                        connection.commit();
                } catch (SQLException e) {
                        connection.rollback();
                        throw e;
                } finally {
                        connection.setAutoCommit(true);
                }
        }

        private void ensureOpen() {
                if (connection == null) {
                        // Self-healing since 1.2.4: a closed/never-opened connection is
                        // reopened on demand instead of failing closed forever (shutdown()
                        // still flips the mod off first, so this cannot resurrect the store
                        // after the server stopped).
                        open();
                }
        }
}
