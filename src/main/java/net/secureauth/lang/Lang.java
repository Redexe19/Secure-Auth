package net.secureauth.lang;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Stream;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import net.fabricmc.loader.api.FabricLoader;
import net.fabricmc.loader.api.ModContainer;
import net.minecraft.network.chat.Component;
import net.minecraft.network.chat.MutableComponent;
import net.minecraft.server.level.ServerPlayer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Server-side message resolver.
 *
 * <p>SecureAuth is a <strong>server-side only</strong> mod: the vanilla client
 * does not know any {@code auth.*} translation key, so every player-visible
 * string must be resolved <em>on the server</em> and sent as a literal
 * component. Translatable components are unusable here — a vanilla client
 * would render the raw key (and in 26.2 the {@code system_chat} encoder
 * rejects malformed argument lists outright).</p>
 *
 * <p>This class loads the very same {@code assets/secureauth/lang/*.json}
 * catalogs that ship inside the mod jar, resolves them per player (using the
 * client language reported in the handshake {@code ClientInformation}), and
 * formats them with {@link String#format}-style placeholders. Legacy
 * {@code §x} color codes embedded in the values are rendered by vanilla
 * clients inside literal text, so colors keep working.</p>
 *
 * <p>Fail-safe by design: a missing catalog, a missing key, a broken format
 * pattern or a {@code null} argument never throws — the worst outcome is the
 * raw key or a partially formatted line, never a dropped packet or a crashed
 * tick.</p>
 */
public final class Lang {

        private static final Logger LOGGER = LoggerFactory.getLogger("secureauth.lang");

        /** Reference catalog used when a player's language has no translation. */
        public static final String DEFAULT_LANGUAGE = "en_us";

        private static final Gson GSON = new Gson();

        /** Loaded catalogs: language code -> (key -> value). */
        private static final Map<String, Map<String, String>> CATALOGS = new ConcurrentHashMap<>();

        /**
         * Keys whose lang values begin with a {@code %s} placeholder reserved for
         * the resolved {@code auth.prefix} brand. All other keys get the brand
         * prepended to the resolved string, so their own {@code %s} placeholders
         * stay bound to the real arguments.
         */
        public static final Set<String> PREFIXED_KEYS = Set.of(
                        "auth.welcome.new",
                        "auth.welcome.returning",
                        "auth.welcome.locked",
                        "auth.register.success",
                        "auth.register.successNoAuto",
                        "auth.login.success",
                        "auth.logout.success",
                        "auth.changepassword.success",
                        "auth.unregister.success",
                        "auth.session.resumed",
                        "auth.release.rescued",
                        "auth.restore.abilities",
                        "auth.admin.reset.success",
                        "auth.admin.unregister.success",
                        "auth.admin.lock.success",
                        "auth.admin.unlock.success",
                        "auth.admin.forcelogout.success",
                        "auth.admin.reload.success");

        private Lang() {
        }

        // ------------------------------------------------------------------
        // Loading
        // ------------------------------------------------------------------

        /**
         * Loads every {@code assets/secureauth/lang/*.json} catalog from this
         * mod's jar (or dev workspace). Called once from the mod initializer;
         * failures degrade to the raw-key fallback instead of disabling the mod.
         */
        public static void load() {
                boolean loaded = false;
                try {
                        List<ModContainer> containers = FabricLoader.getInstance().getAllMods().stream()
                                        .filter(c -> c.getMetadata().getId().equals("secureauth"))
                                        .toList();
                        for (ModContainer container : containers) {
                                for (Path root : container.getRootPaths()) {
                                        loaded |= loadDirectory(root.resolve("assets/secureauth/lang"));
                                }
                        }
                } catch (RuntimeException e) {
                        LOGGER.warn("SecureAuth language catalog discovery failed; falling back to raw keys", e);
                }
                if (!loaded) {
                        // Last-resort: the classpath also exposes the jar resources.
                        for (String code : new String[] { DEFAULT_LANGUAGE, "zh_cn", "ja_jp", "ru_ru" }) {
                                try (InputStream in = Lang.class.getClassLoader()
                                                .getResourceAsStream("assets/secureauth/lang/" + code + ".json")) {
                                        if (in != null) {
                                                loadCatalog(code, new BufferedReader(
                                                                new InputStreamReader(in, StandardCharsets.UTF_8)));
                                        }
                                } catch (IOException | RuntimeException e) {
                                        LOGGER.warn("SecureAuth could not read the '{}' catalog", code, e);
                                }
                        }
                }
                if (CATALOGS.isEmpty()) {
                        LOGGER.warn("SecureAuth found no language catalogs; player messages will show raw keys");
                } else {
                        LOGGER.info("SecureAuth language catalogs loaded: {} locales, {} keys in the reference catalog",
                                        CATALOGS.keySet(), CATALOGS.get(DEFAULT_LANGUAGE).size());
                }
        }

        private static boolean loadDirectory(Path dir) {
                if (!Files.isDirectory(dir)) {
                        return false;
                }
                boolean any = false;
                try (Stream<Path> files = Files.list(dir)) {
                        for (Path file : files.filter(f -> f.getFileName().toString().endsWith(".json")).toList()) {
                                String code = file.getFileName().toString();
                                code = code.substring(0, code.length() - ".json".length()).toLowerCase(Locale.ROOT);
                                try (BufferedReader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
                                        loadCatalog(code, reader);
                                        any = true;
                                } catch (IOException | RuntimeException e) {
                                        LOGGER.warn("SecureAuth could not parse the language file {}", file, e);
                                }
                        }
                } catch (IOException | RuntimeException e) {
                        LOGGER.warn("SecureAuth could not list the language directory {}", dir, e);
                }
                return any;
        }

        private static void loadCatalog(String code, BufferedReader reader) {
                Map<String, String> parsed = GSON.fromJson(reader, new TypeToken<Map<String, String>>() {
                }.getType());
                if (parsed != null && !parsed.isEmpty()) {
                        CATALOGS.put(code, new ConcurrentHashMap<>(parsed));
                }
        }

        // ------------------------------------------------------------------
        // Resolution
        // ------------------------------------------------------------------

        /** The catalog language of a player: their client language when translated, else {@code en_us}. */
        public static String languageOf(ServerPlayer player) {
                if (player != null) {
                        try {
                                String language = player.clientInformation().language();
                                if (language != null && CATALOGS.containsKey(language.toLowerCase(Locale.ROOT))) {
                                        return language.toLowerCase(Locale.ROOT);
                                }
                        } catch (RuntimeException ignored) {
                                // Player not fully connected (or an unexpected state): default catalog.
                        }
                }
                return DEFAULT_LANGUAGE;
        }

        /** The pattern for a key in a catalog (missing keys fall back to the reference, then the raw key). */
        public static String pattern(String language, String key) {
                Map<String, String> catalog = CATALOGS.get(language);
                String value = catalog != null ? catalog.get(key) : null;
                if (value == null) {
                        catalog = CATALOGS.get(DEFAULT_LANGUAGE);
                        value = catalog != null ? catalog.get(key) : null;
                }
                return value != null ? value : key;
        }

        /** The resolved brand prefix (reference catalog). */
        public static String prefix() {
                return pattern(DEFAULT_LANGUAGE, "auth.prefix");
        }

        /**
         * Resolves one message for a player into plain text (brand included).
         * Never throws; unresolved keys render as their literal key name.
         */
        public static String text(ServerPlayer player, String key, Object... args) {
                return branded(languageOf(player), key, args);
        }

        /** Console variant: always the reference catalog. */
        public static String textForConsole(String key, Object... args) {
                return branded(DEFAULT_LANGUAGE, key, args);
        }

        private static String branded(String language, String key, Object... args) {
                String pattern = pattern(language, key);
                String result;
                if (PREFIXED_KEYS.contains(key)) {
                        Object[] branded = new Object[args.length + 1];
                        branded[0] = pattern(language, "auth.prefix");
                        for (int i = 0; i < args.length; i++) {
                                branded[i + 1] = args[i];
                        }
                        result = format(language, key, pattern, branded);
                } else {
                        result = pattern(language, "auth.prefix") + format(language, key, pattern, args);
                }
                return result;
        }

        /**
         * A literal component carrying the resolved text. The vanilla client
         * renders legacy {@code §} codes found inside literal components, so
         * the color markup in the catalogs keeps working.
         */
        public static MutableComponent comp(ServerPlayer player, String key, Object... args) {
                return Component.literal(text(player, key, args));
        }

        /** Console variant of {@link #comp}. */
        public static MutableComponent compForConsole(String key, Object... args) {
                return Component.literal(textForConsole(key, args));
        }

        /**
         * An unbranded literal component (panel titles, item names, lore lines).
         * {@code null} arguments are dropped by {@link #format}.
         */
        public static MutableComponent plain(ServerPlayer player, String key, Object... args) {
                String language = languageOf(player);
                return Component.literal(format(language, key, pattern(language, key), args));
        }

        // ------------------------------------------------------------------
        // Formatting
        // ------------------------------------------------------------------

        /**
         * Formats a pattern with {@code %s}-style placeholders. {@code null}
         * arguments become empty strings (never the encoder-breaking
         * {@code null} component of the old translatable pipeline); a broken
         * pattern degrades to the raw pattern plus the argument values.
         */
        private static String format(String language, String key, String pattern, Object... args) {
                if (args == null || args.length == 0) {
                        return pattern;
                }
                Object[] sanitized = new Object[args.length];
                for (int i = 0; i < args.length; i++) {
                        sanitized[i] = args[i] == null ? "" : args[i];
                }
                try {
                        return String.format(pattern, sanitized);
                } catch (RuntimeException e) {
                        // A pattern/argument mismatch must never break packet delivery.
                        StringBuilder fallback = new StringBuilder(pattern);
                        for (Object arg : sanitized) {
                                fallback.append(' ').append(arg);
                        }
                        return fallback.toString();
                }
        }
}
