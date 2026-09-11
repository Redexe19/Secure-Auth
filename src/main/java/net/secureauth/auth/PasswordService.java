package net.secureauth.auth;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import net.secureauth.config.AuthConfig;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

/**
 * Password hashing service.
 *
 * <p>Primary algorithm: Argon2id (Bouncy Castle, pure Java, bundled with the mod).
 * Fallback: PBKDF2WithHmacSHA256 from the JDK, used when the configured algorithm
 * is "pbkdf2" or when Bouncy Castle is unavailable for any reason.</p>
 *
 * <p>Security properties:</p>
 * <ul>
 *   <li>Random salt per password.</li>
 *   <li>Verification is constant-time via {@link MessageDigest#isEqual(byte[], byte[])}.</li>
 *   <li>Passwords never appear in {@code toString()}, exceptions or logs.</li>
 *   <li>Hash parameters are stored alongside the hash so they can be upgraded later.</li>
 * </ul>
 */
public final class PasswordService {

        public static final String ALGORITHM_ARGON2ID = "argon2id";
        public static final String ALGORITHM_PBKDF2 = "pbkdf2";
        public static final int FORMAT_VERSION = 1;

        private static final SecureRandom RANDOM = new SecureRandom();
        private static volatile boolean argon2Available = true;

        private final AuthConfig config;

        public PasswordService(AuthConfig config) {
                this.config = config;
        }

        /** Immutable record of everything needed to verify a password later. */
        public record PasswordHash(String algorithm, int version, byte[] salt, byte[] hash, String params) {
                @Override
                public String toString() {
                        // Defensive: never expose salt/hash through accidental logging.
                        return "PasswordHash[algorithm=" + algorithm + ", version=" + version
                                        + ", params=" + params + ", salt=***, hash=***]";
                }
        }

        public boolean isArgon2Available() {
                if (!argon2Available) {
                        return false;
                }
                try {
                        Class.forName("org.bouncycastle.crypto.generators.Argon2BytesGenerator");
                        return true;
                } catch (ClassNotFoundException e) {
                        argon2Available = false;
                        return false;
                }
        }

        /** Hashes a password with the configured algorithm. */
        public PasswordHash hash(String password) {
                String algorithm = configuredAlgorithm();
                if (ALGORITHM_ARGON2ID.equals(algorithm) && isArgon2Available()) {
                        byte[] salt = randomSalt(config.password.argon2.saltLength);
                        byte[] hash = argon2Derive(password, salt, config.password.argon2);
                        String params = config.password.argon2.iterations + "," + config.password.argon2.memoryKiB
                                        + "," + config.password.argon2.parallelism + "," + config.password.argon2.outputLength;
                        return new PasswordHash(ALGORITHM_ARGON2ID, FORMAT_VERSION, salt, hash, params);
                }
                byte[] salt = randomSalt(config.password.pbkdf2.saltLength);
                byte[] hash = pbkdf2Derive(password, salt, config.password.pbkdf2);
                String params = config.password.pbkdf2.iterations + "," + config.password.pbkdf2.outputLength;
                return new PasswordHash(ALGORITHM_PBKDF2, FORMAT_VERSION, salt, hash, params);
        }

        /**
         * Verifies a candidate password against a stored hash, using the parameters
         * stored at hashing time. Constant-time comparison.
         */
        public boolean verify(PasswordHash stored, String candidate) {
                if (stored == null || candidate == null || stored.salt() == null || stored.hash() == null) {
                        return false;
                }
                try {
                        byte[] computed;
                        if (ALGORITHM_ARGON2ID.equals(stored.algorithm())) {
                                if (!isArgon2Available()) {
                                        return false;
                                }
                                computed = argon2Derive(candidate, stored.salt(), parseArgon2Params(stored.params(), stored.hash().length));
                        } else if (ALGORITHM_PBKDF2.equals(stored.algorithm())) {
                                computed = pbkdf2Derive(candidate, stored.salt(), parsePbkdf2Params(stored.params(), stored.hash().length));
                        } else {
                                return false;
                        }
                        return MessageDigest.isEqual(computed, stored.hash());
                } catch (RuntimeException e) {
                        // Corrupt params or unexpected derivation failure: fail closed.
                        return false;
                }
        }

        // ------------------------------------------------------------------
        // Argon2id
        // ------------------------------------------------------------------

        private byte[] argon2Derive(String password, byte[] salt, AuthConfig.PasswordSection.Argon2Params params) {
                Argon2Parameters bcParams = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                                .withIterations(params.iterations)
                                .withMemoryAsKB(params.memoryKiB)
                                .withParallelism(params.parallelism)
                                .withSalt(salt)
                                .build();
                Argon2BytesGenerator generator = new Argon2BytesGenerator();
                generator.init(bcParams);
                byte[] output = new byte[params.outputLength];
                generator.generateBytes(password.toCharArray(), output);
                return output;
        }

        private AuthConfig.PasswordSection.Argon2Params parseArgon2Params(String params, int outputLength) {
                String[] parts = params.split(",");
                if (parts.length < 4) {
                        throw new IllegalArgumentException("Corrupted Argon2 parameters");
                }
                AuthConfig.PasswordSection.Argon2Params p = new AuthConfig.PasswordSection.Argon2Params();
                p.iterations = Math.max(1, Integer.parseInt(parts[0]));
                p.memoryKiB = Math.max(8, Integer.parseInt(parts[1]));
                p.parallelism = Math.max(1, Integer.parseInt(parts[2]));
                p.outputLength = outputLength > 0 ? outputLength : Integer.parseInt(parts[3]);
                return p;
        }

        // ------------------------------------------------------------------
        // PBKDF2 (JDK fallback)
        // ------------------------------------------------------------------

        private byte[] pbkdf2Derive(String password, byte[] salt, AuthConfig.PasswordSection.Pbkdf2Params params) {
                try {
                        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, params.iterations, params.outputLength * 8);
                        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                        return factory.generateSecret(spec).getEncoded();
                } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                        throw new IllegalStateException("PBKDF2 unavailable in this JVM", e);
                }
        }

        private AuthConfig.PasswordSection.Pbkdf2Params parsePbkdf2Params(String params, int outputLength) {
                String[] parts = params.split(",");
                if (parts.length < 2) {
                        throw new IllegalArgumentException("Corrupted PBKDF2 parameters");
                }
                AuthConfig.PasswordSection.Pbkdf2Params p = new AuthConfig.PasswordSection.Pbkdf2Params();
                p.iterations = Math.max(1, Integer.parseInt(parts[0]));
                p.outputLength = outputLength > 0 ? outputLength : Integer.parseInt(parts[1]);
                return p;
        }

        private String configuredAlgorithm() {
                return ALGORITHM_PBKDF2.equalsIgnoreCase(config.password.algorithm) ? ALGORITHM_PBKDF2 : ALGORITHM_ARGON2ID;
        }

        private static byte[] randomSalt(int length) {
                byte[] salt = new byte[Math.max(8, length)];
                RANDOM.nextBytes(salt);
                return salt;
        }

        // ------------------------------------------------------------------
        // Shared helpers
        // ------------------------------------------------------------------

        public static byte[] sha256(byte[] input) {
                try {
                        return MessageDigest.getInstance("SHA-256").digest(input);
                } catch (NoSuchAlgorithmException e) {
                        throw new IllegalStateException(e);
                }
        }

        public static String toHex(byte[] bytes) {
                StringBuilder sb = new StringBuilder(bytes.length * 2);
                for (byte b : bytes) {
                        sb.append(Character.forDigit((b >> 4) & 0xF, 16));
                        sb.append(Character.forDigit(b & 0xF, 16));
                }
                return sb.toString();
        }

        public static String toBase64(byte[] bytes) {
                return Base64.getEncoder().encodeToString(bytes);
        }

        public static byte[] fromBase64(String value) {
                return Base64.getDecoder().decode(value);
        }

        /** Wipes a char array best-effort (passwords arrive as Strings, see README). */
        public static void wipe(char[] chars) {
                Arrays.fill(chars, '\0');
        }
}
