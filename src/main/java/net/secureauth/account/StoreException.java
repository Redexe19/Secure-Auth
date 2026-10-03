package net.secureauth.account;

/**
 * Thrown when the account database is unavailable or an operation fails.
 * Callers must treat this as <strong>fail closed</strong>: never authenticate a
 * player when the storage layer cannot be read.
 */
public class StoreException extends RuntimeException {

        public StoreException(String message) {
                super(message);
        }

        public StoreException(String message, Throwable cause) {
                super(message, cause);
        }

        /**
         * Compact diagnostic text for logs (since 1.2.4): walks the cause chain to
         * the deepest entry and reports {@code ClassName: message}. This is what
         * turns a swallowed "service unavailable" into a visible root cause such
         * as {@code SQLiteException: database disk is full} — the actual reason
         * behind the flaky reset failures the admins kept seeing.
         */
        public static String describe(Throwable failure) {
                if (failure == null) {
                        return "unknown";
                }
                Throwable root = failure;
                while (root.getCause() != null && root.getCause() != root) {
                        root = root.getCause();
                }
                String text = root.getMessage() == null ? failure.getMessage() : root.getMessage();
                if (text == null || text.isBlank()) {
                        text = root.getClass().getSimpleName();
                }
                return root.getClass().getSimpleName() + ": " + text;
        }
}
