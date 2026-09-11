package net.secureauth.account;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import net.secureauth.auth.PasswordService;

/**
 * JDBC repository for {@link Account} rows. All mutating operations run inside
 * transactions provided by {@link AccountDatabase#transactional}.
 */
public final class AccountRepository {

        private final AccountDatabase database;

        public AccountRepository(AccountDatabase database) {
                this.database = database;
        }

        // ------------------------------------------------------------------
        // Lookups
        // ------------------------------------------------------------------

        public Optional<Account> findByUsernameNorm(String usernameNorm) {
                final String normalized = normalize(usernameNorm);
                final Account[] out = new Account[1];
                database.transactional(conn -> {
                        try (PreparedStatement ps = conn.prepareStatement(
                                        "SELECT id, username_norm, username_display, uuid_offline, algorithm, hash_version, salt, hash, hash_params, "
                                                        + "created_at, last_login, failed_attempts, lockout_until, locked FROM accounts WHERE username_norm = ?")) {
                                ps.setString(1, normalized);
                                try (ResultSet rs = ps.executeQuery()) {
                                        if (rs.next()) {
                                                out[0] = readAccount(rs);
                                        }
                                }
                        } catch (SQLException e) {
                                throw new StoreException("Failed to look up account", e);
                        }
                });
                return Optional.ofNullable(out[0]);
        }

        public boolean exists(String usernameNorm) {
                return findByUsernameNorm(usernameNorm).isPresent();
        }

        public long countAccounts() {
                final long[] out = new long[1];
                database.transactional(conn -> {
                        try (Statement stmt = conn.createStatement(); ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM accounts")) {
                                out[0] = rs.next() ? rs.getLong(1) : 0;
                        } catch (SQLException e) {
                                throw new StoreException("Failed to count accounts", e);
                        }
                });
                return out[0];
        }

        /** Page through accounts for {@code /auth list}. Returns [username_display, lastLoginIso] pairs. */
        public List<String[]> listAccounts(int offset, int limit) {
                List<String[]> out = new ArrayList<>();
                database.transactional(conn -> {
                        try (PreparedStatement ps = conn.prepareStatement(
                                        "SELECT username_display, last_login FROM accounts ORDER BY username_norm LIMIT ? OFFSET ?")) {
                                ps.setInt(1, Math.max(1, limit));
                                ps.setInt(2, Math.max(0, offset));
                                try (ResultSet rs = ps.executeQuery()) {
                                        while (rs.next()) {
                                                Long lastLogin = rs.getObject(2) == null ? null : rs.getLong(2);
                                                out.add(new String[]{rs.getString(1), lastLogin == null ? "never" : java.time.Instant.ofEpochMilli(lastLogin).toString()});
                                        }
                                }
                        } catch (SQLException e) {
                                throw new StoreException("Failed to list accounts", e);
                        }
                });
                return out;
        }

        // ------------------------------------------------------------------
        // Mutation
        // ------------------------------------------------------------------

        /** Creates a new account; assigns the generated id. Fails if the name exists. */
        public Account create(String usernameDisplay, String offlineUuid, PasswordService.PasswordHash hash) {
                String norm = normalize(usernameDisplay);
                Account account = new Account(0, norm, usernameDisplay, offlineUuid,
                                hash.algorithm(), hash.version(), hash.salt(), hash.hash(), hash.params(),
                                System.currentTimeMillis(), null, 0, 0, false);
                database.transactional(conn -> {
                        try (PreparedStatement exists = conn.prepareStatement("SELECT 1 FROM accounts WHERE username_norm = ?")) {
                                exists.setString(1, norm);
                                try (ResultSet rs = exists.executeQuery()) {
                                        if (rs.next()) {
                                                throw new IllegalArgumentException("ACCOUNT_EXISTS");
                                        }
                                }
                        } catch (SQLException e) {
                                throw new StoreException("Failed to check account existence", e);
                        }
                        try (PreparedStatement ps = conn.prepareStatement(
                                        "INSERT INTO accounts (username_norm, username_display, uuid_offline, algorithm, hash_version, salt, hash, hash_params, "
                                                        + "created_at, last_login, failed_attempts, lockout_until, locked) VALUES (?,?,?,?,?,?,?,?,?,?,0,0,0)",
                                        Statement.RETURN_GENERATED_KEYS)) {
                                ps.setString(1, norm);
                                ps.setString(2, usernameDisplay);
                                ps.setString(3, offlineUuid);
                                ps.setString(4, hash.algorithm());
                                ps.setInt(5, hash.version());
                                ps.setBytes(6, hash.salt());
                                ps.setBytes(7, hash.hash());
                                ps.setString(8, hash.params());
                                ps.setLong(9, account.createdAt());
                                ps.setObject(10, null);
                                ps.executeUpdate();
                                try (ResultSet keys = ps.getGeneratedKeys()) {
                                        if (keys.next()) {
                                                account.assignId(keys.getLong(1));
                                        }
                                }
                        } catch (SQLException e) {
                                throw new StoreException("Failed to create account", e);
                        }
                });
                return account;
        }

        /** Marks a successful login: resets failures, clears lockout, updates last_login. */
        public void recordLoginSuccess(long accountId) {
                database.transactional(conn -> update(conn, accountId,
                                "UPDATE accounts SET last_login = ?, failed_attempts = 0, lockout_until = 0 WHERE id = ?",
                                System.currentTimeMillis()));
        }

        /**
         * Records a failed login attempt. Returns the resulting failure count.
         */
        public int recordLoginFailure(long accountId) {
                final int[] count = new int[1];
                database.transactional(conn -> {
                        try {
                                try (PreparedStatement ps = conn.prepareStatement(
                                                "UPDATE accounts SET failed_attempts = failed_attempts + 1 WHERE id = ?");
                                        PreparedStatement read = conn.prepareStatement(
                                                        "SELECT failed_attempts FROM accounts WHERE id = ?")) {
                                        ps.setLong(1, accountId);
                                        ps.executeUpdate();
                                        read.setLong(1, accountId);
                                        try (ResultSet rs = read.executeQuery()) {
                                                count[0] = rs.next() ? rs.getInt(1) : 0;
                                        }
                                }
                        } catch (SQLException e) {
                                throw new StoreException("Failed to record login failure", e);
                        }
                });
                return count[0];
        }

        /** Applies a temporary lockout that ends at the given epoch millisecond. */
        public void setLockout(long accountId, long untilEpochMillis) {
                database.transactional(conn -> update(conn, accountId,
                                "UPDATE accounts SET lockout_until = ?, locked = 0 WHERE id = ?", untilEpochMillis));
        }

        public void setLocked(long accountId, boolean locked) {
                database.transactional(conn -> update(conn, accountId,
                                "UPDATE accounts SET locked = ?, lockout_until = 0, failed_attempts = 0 WHERE id = ?", locked ? 1 : 0));
        }

        public void clearLockout(long accountId) {
                database.transactional(conn -> update(conn, accountId,
                                "UPDATE accounts SET lockout_until = 0, failed_attempts = 0 WHERE id = ?", 0));
        }

        /** Replaces the password hash of an account. */
        public void updatePassword(long accountId, PasswordService.PasswordHash hash) {
                database.transactional(conn -> {
                        try (PreparedStatement ps = conn.prepareStatement(
                                        "UPDATE accounts SET algorithm = ?, hash_version = ?, salt = ?, hash = ?, hash_params = ?, "
                                                        + "failed_attempts = 0, lockout_until = 0 WHERE id = ?")) {
                                ps.setString(1, hash.algorithm());
                                ps.setInt(2, hash.version());
                                ps.setBytes(3, hash.salt());
                                ps.setBytes(4, hash.hash());
                                ps.setString(5, hash.params());
                                ps.setLong(6, accountId);
                                ps.executeUpdate();
                        } catch (SQLException e) {
                                throw new StoreException("Failed to update password", e);
                        }
                });
        }

        public boolean delete(long accountId) {
                final boolean[] deleted = new boolean[1];
                database.transactional(conn -> {
                        try (PreparedStatement ps = conn.prepareStatement("DELETE FROM accounts WHERE id = ?")) {
                                ps.setLong(1, accountId);
                                deleted[0] = ps.executeUpdate() > 0;
                        } catch (SQLException e) {
                                throw new StoreException("Failed to delete account", e);
                        }
                });
                return deleted[0];
        }

        // ------------------------------------------------------------------
        // Login attempt journal (for auditing / per-IP analysis)
        // ------------------------------------------------------------------

        public void recordAttempt(Long accountId, String username, String ip, boolean success, String reason) {
                database.transactional(conn -> {
                        try (PreparedStatement ps = conn.prepareStatement(
                                        "INSERT INTO login_attempts (account_id, username, ip, success, reason, timestamp) VALUES (?,?,?,?,?,?)")) {
                                if (accountId == null) {
                                        ps.setObject(1, null);
                                } else {
                                        ps.setLong(1, accountId);
                                }
                                ps.setString(2, username);
                                ps.setString(3, ip);
                                ps.setInt(4, success ? 1 : 0);
                                ps.setString(5, reason);
                                ps.setLong(6, System.currentTimeMillis());
                                ps.executeUpdate();
                        } catch (SQLException e) {
                                throw new StoreException("Failed to journal login attempt", e);
                        }
                });
        }

        // ------------------------------------------------------------------
        // Helpers
        // ------------------------------------------------------------------

        private static void update(java.sql.Connection conn, long accountId, String sql, Object... args) {
                try (PreparedStatement ps = conn.prepareStatement(sql)) {
                        int index = 1;
                        for (Object arg : args) {
                                ps.setObject(index++, arg);
                        }
                        ps.setLong(index, accountId);
                        ps.executeUpdate();
                } catch (SQLException e) {
                        throw new StoreException("Failed to update account", e);
                }
        }

        private static Account readAccount(ResultSet rs) throws SQLException {
                Long lastLogin = rs.getObject("last_login") == null ? null : rs.getLong("last_login");
                return new Account(
                                rs.getLong("id"),
                                rs.getString("username_norm"),
                                rs.getString("username_display"),
                                rs.getString("uuid_offline"),
                                rs.getString("algorithm"),
                                rs.getInt("hash_version"),
                                rs.getBytes("salt"),
                                rs.getBytes("hash"),
                                rs.getString("hash_params"),
                                rs.getLong("created_at"),
                                lastLogin,
                                rs.getInt("failed_attempts"),
                                rs.getLong("lockout_until"),
                                rs.getInt("locked") != 0);
        }

        /** Canonical case-insensitive username key. */
        public static String normalize(String username) {
                return username == null ? "" : username.toLowerCase(java.util.Locale.ROOT);
        }
}
