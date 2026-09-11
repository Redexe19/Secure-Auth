package net.secureauth.world;

import java.util.Optional;
import net.minecraft.core.BlockPos;
import net.minecraft.core.registries.BuiltInRegistries;
import net.minecraft.core.registries.Registries;
import net.minecraft.network.chat.Component;
import net.minecraft.resources.Identifier;
import net.minecraft.resources.ResourceKey;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.level.ServerLevel;
import net.minecraft.server.level.ServerPlayer;
import net.minecraft.world.entity.Entity;
import net.minecraft.world.effect.MobEffectInstance;
import net.minecraft.world.effect.MobEffects;
import net.minecraft.world.level.GameType;
import net.minecraft.world.level.Level;
import net.minecraft.world.level.block.Block;
import net.minecraft.world.level.block.Blocks;
import net.minecraft.world.level.block.state.BlockState;
import net.minecraft.world.level.chunk.LevelChunk;
import net.minecraft.world.level.chunk.LevelChunkSection;
import net.minecraft.world.level.portal.TeleportTransition;
import net.minecraft.world.phys.Vec3;
import net.secureauth.auth.AuthSession;
import net.secureauth.config.AuthConfig;
import net.secureauth.security.SecurityEvent;
import net.secureauth.security.SecurityLogger;
import net.minecraft.world.level.storage.LevelData;

/**
 * Pre-authentication world isolation.
 *
 * <p>Players are moved into a dedicated {@code secureauth:auth} dimension — an
 * overworld-style void (blue sky, sun and clouds, no terrain, no features) whose
 * only block is the stone platform under their feet — for the entire
 * authentication phase, so no chunks, entities, structures or player positions
 * of the real world are ever synced to an unauthenticated client. After
 * authentication the original dimension, position, rotation, game mode and
 * movement flags are restored from the server-side snapshot.</p>
 */
public final class AuthWorldManager {

        public static final ResourceKey<Level> AUTH_DIMENSION =
                        ResourceKey.create(Registries.DIMENSION, Identifier.fromNamespaceAndPath("secureauth", "auth"));

        /**
         * Static mirror of {@code worldProtection.clearAuthEntities} read by the
         * {@code ServerLevelMixin} entity-birth guard. Defaults to {@code true} so the
         * guard is active (fail closed) from class initialisation until the config is
         * loaded; SecureAuth updates it on load and on {@code /auth reload}.
         */
        private static volatile boolean entityGuard = true;

        /** Updates the mixin-visible entity guard flag. */
        public static void setEntityGuard(boolean enabled) {
                entityGuard = enabled;
        }

        /** True (fail closed default) when non-player entities must not enter the auth dimension. */
        public static boolean entityGuard() {
                return entityGuard;
        }

        /** Maximum block removals per purifier pass (keeps one tick cheap even with junk chunks). */
        private static final int PURIFY_BUDGET = 20_000;

        /** Minimum seconds between two "void purified" log lines. */
        private static final long PURIFY_LOG_INTERVAL_MS = 60_000L;

        /** Diagnostic counter for the first purifier sweeps (log visibility during validation). */
        private static final java.util.concurrent.atomic.AtomicInteger PURIFY_DEBUG =
                        new java.util.concurrent.atomic.AtomicInteger();

        private final AuthConfig config;
        private final SecurityLogger logger;
        private boolean platformWarned;
        private long lastPurifyLogAt;

        public AuthWorldManager(AuthConfig config, SecurityLogger logger) {
                this.config = config;
                this.logger = logger;
        }

        // ------------------------------------------------------------------
        // Dimension access
        // ------------------------------------------------------------------

        public ServerLevel authLevel(MinecraftServer server) {
                return server.getLevel(AUTH_DIMENSION);
        }

        // ------------------------------------------------------------------
        // Quarantine / restore
        // ------------------------------------------------------------------

        /**
         * Moves the player into the authentication holding area and freezes their
         * dangerous state. Falls back to "freeze in place" if the dimension is missing.
         *
         * <p>When the player is ALREADY inside the auth dimension at capture time
         * (they rejoined after a timeout/quit while quarantined, or a crash left
         * their save data pointing into the auth area), the snapshot is replaced
         * by their respawn position — the auth dimension must never become the
         * "original location" a successful login restores them to, or they would
         * authenticate straight into the void.</p>
         */
        public void quarantine(ServerPlayer player, AuthSession session) {
                // Re-arm the one-shot ability reconciliation: the next login will
                // need it again (logout/unregister reuse the same session object).
                session.abilitiesReconciled = false;
                OriginalLocation original = OriginalLocation.capture(player);
                if (original != null && original.dimension == AUTH_DIMENSION) {
                        original = respawnLocation(player);
                        logger.log(SecurityEvent.SANDBOX_ESCAPE_CORRECTED, session.usernameNorm, session.ip,
                                        "capture_in_auth_dimension; using respawn");
                }
                // 1.2.3: a snapshot carrying BOTH sandbox flags is leftover quarantine
                // state from a pre-1.2.3 save (the flags used to leak into the
                // disconnect save). Sanitize it so a successful login restores a
                // normal, falling, damageable player — this also self-heals player
                // data that is already poisoned.
                if (original != null && original.invulnerable && original.noGravity) {
                        original = OriginalLocation.repairSandboxResidue(original);
                        logger.log(SecurityEvent.SANDBOX_ESCAPE_CORRECTED, session.usernameNorm, session.ip,
                                        "sandbox_flag_residue_repaired");
                }
                session.originalLocation = original;

                ServerLevel authLevel = authLevel(player.level().getServer());
                if (authLevel == null || !"auth_dimension".equals(config.worldProtection.isolationMode)) {
                        // Fail-closed fallback: the player stays where they are but is still
                        // immobilised, invulnerable, filtered and command-blocked.
                        freezeInPlace(session);
                        logger.log(SecurityEvent.PLAYER_QUARANTINED, session.usernameNorm, session.ip,
                                        "mode=freeze_in_place");
                        return;
                }

                BlockPos spawn = ensurePlatform(authLevel);
                session.authLevel = authLevel;
                session.authSpawn = spawn;

                // Feet land ON TOP of the platform block (y + 1), never inside it —
                // and inside the bedrock cell (since 1.2.4), never on its roof.
                teleport(player, authLevel, spawn.getX() + 0.5, spawn.getY() + 1.0, spawn.getZ() + 0.5, 0.0F, 0.0F);
                player.setInvulnerable(true);
                player.setNoGravity(true);
                player.stopSleeping();
                player.setDeltaMovement(Vec3.ZERO);
                resetFallDistanceSafely(player);
                // Adventure mode (since 1.2.2): the CLIENT refuses to break or place blocks
                // and to interact with the world on its own, so the pre-auth sandbox looks
                // and feels sealed instead of only being sealed server-side (client-side
                // prediction used to make ghost breaks look possible).
                player.setGameMode(GameType.ADVENTURE);
                applyBlindness(player);
                logger.log(SecurityEvent.PLAYER_QUARANTINED, session.usernameNorm, session.ip,
                                "mode=auth_dimension");
        }

        /** Freezes the player without teleporting (fallback isolation mode). */
        private void freezeInPlace(AuthSession session) {
                ServerPlayer player = session.player;
                session.authLevel = (ServerLevel) player.level();
                session.authSpawn = player.blockPosition();
                player.setInvulnerable(true);
                player.setNoGravity(true);
                player.setDeltaMovement(Vec3.ZERO);
                player.setGameMode(GameType.ADVENTURE);
                applyBlindness(player);
        }

        /**
         * Restores the player to the captured original location after a successful
         * authentication. When the snapshot is missing (should never happen) the
         * player is sent to the overworld spawn instead — never into the void. A
         * snapshot that points into the auth dimension itself is treated as
         * missing for the same reason.
         */
        public void restore(ServerPlayer player, AuthSession session) {
                OriginalLocation original = session.originalLocation;
                if (original != null && original.dimension == AUTH_DIMENSION) {
                        // A snapshot pointing into the auth dimension is treated as missing:
                        // restoring it would authenticate the player straight into the void.
                        original = null;
                }
                // Since 1.2.4 the defensive fallback is the player's respawn anchor
                // (bed) when one exists — a nicer place to wake up than the raw
                // overworld spawn, and still never inside the auth dimension.
                if (original == null) {
                        original = respawnLocation(player);
                }
                MinecraftServer server = player.level().getServer();
                // The sandbox effects (blindness, adventure) are lifted BEFORE the player
                // is moved back, and the original game type is restored either way.
                clearBlindness(player);
                player.setGameMode(original != null ? original.gameMode : GameType.SURVIVAL);
                if (original == null || server == null) {
                        // Defensive fallback (the snapshot is always captured; this path
                        // should be unreachable): send the player to the overworld spawn.
                        ServerLevel overworld = server != null ? server.overworld() : null;
                        if (overworld != null) {
                                BlockPos spawn = fallbackSpawn(overworld);
                                teleport(player, overworld, spawn.getX() + 0.5, spawn.getY(), spawn.getZ() + 0.5, 0, 0);
                        }
                } else {
                        ServerLevel target = server.getLevel(original.dimension);
                        if (target == null) {
                                target = server.overworld();
                        }
                        teleport(player, target, original.x, original.y, original.z, original.yaw, original.pitch);
                        player.setGameMode(original.gameMode);
                }

                player.setInvulnerable(original != null && original.invulnerable);
                player.setNoGravity(original != null && original.noGravity);
                player.setDeltaMovement(Vec3.ZERO);
                // A rescued player may have been mid-fall inside the void when the
                // release fired: without this the accumulated fall distance would
                // come along and hit them the moment they land in the real world.
                resetFallDistanceSafely(player);
                logger.log(SecurityEvent.AUTH_STATE_RESTORED, session.usernameNorm, session.ip);
        }

        /**
         * Automatic rescue for an AUTHENTICATED player who is still physically
         * inside the auth dimension (since 1.2.4). Two callers:
         * <ul>
         *   <li>the release watchdog in {@code AuthManager.tick} (5 s default,
         *       re-checked every second): a lag-failed dimension transfer during
         *       login can no longer strand anyone — the player is sent back to
         *       where they were, or to their respawn anchor;</li>
         *   <li>the session-resume join path: a rejoining trusted player whose
         *       save data still points into the auth dimension (they disconnected
         *       while a release was pending) is moved out immediately instead of
         *       spawning mid-fall inside the void.</li>
         * </ul>
         * Returns true when a rescue actually happened (the player was inside the
         * auth dimension and was moved out).
         */
        public boolean rescueFromAuthDimension(ServerPlayer player, AuthSession session) {
                if (player == null || player.level().dimension() != AUTH_DIMENSION) {
                        return false;
                }
                if (session.originalLocation == null || session.originalLocation.dimension == AUTH_DIMENSION) {
                        session.originalLocation = respawnLocation(player);
                }
                restore(player, session);
                return true;
        }

        /**
         * One-shot ability reconciliation for an authenticated player who is
         * OUTSIDE the auth dimension: whatever sandbox restrictions are still
         * stuck on the entity are repaired from the pre-quarantine snapshot.
         * The sandbox's entity-level state is lifted exactly once, at auth
         * success — when that restore misses the live entity (a cross-dimension
         * transfer recreated the ServerPlayer between ticks) or half-fails
         * under lag, the player would otherwise walk the real world forever
         * with adventure's "cannot interact, cannot break" while every
         * packet-level restore (tab list) already worked.
         *
         * <p>Repairs, using the pre-quarantine snapshot as the source of truth:</p>
         * <ul>
         *   <li>the sandbox's ADVENTURE game type — only when the truth source proves
         *       the player was not in adventure before the quarantine (a legitimate
         *       adventure-mode player is never touched). The truth is the snapshot,
         *       or for a resumed session (no snapshot) the auth-time game type the
         *       resume record remembered — and then only with a corroborating
         *       signature, so an operator's deliberate adventure survives;</li>
         *   <li>the mod's own blindness instance — matched by its exact signature
         *       (infinite, ambient, particle-free), so a blindness another operator
         *       deliberately applied survives;</li>
         *   <li>the sandbox's invulnerable + no-gravity PAIR — the exact flag
         *       combination quarantine applies, reset to the snapshot's values;
         *       single-flag states a player genuinely uses are never touched.</li>
         * </ul>
         *
         * <p>Returns true when anything was actually repaired. The caller marks
         * the session reconciled either way (one-shot per quarantine), which is
         * what keeps this safety net from ever fighting later operator
         * game-mode or effect changes on a fully released player.</p>
         */
        public boolean reconcileOutsideSandbox(ServerPlayer player, AuthSession session) {
                OriginalLocation snapshot = session.originalLocation;
                boolean repaired = false;

                // Evaluate the corroborating residue signature FIRST: the mod's own
                // blindness instance and/or the invulnerable+no-gravity pair. A resumed
                // session has no snapshot, so its game-type repair requires this
                // corroboration — an operator's deliberate adventure (no signature)
                // must never be touched.
                MobEffectInstance blindness = null;
                try {
                        blindness = player.getEffect(MobEffects.BLINDNESS);
                } catch (RuntimeException ignored) {
                        // Effect probing is best-effort; nothing to repair then.
                }
                boolean blindnessResidue = blindness != null && isSandboxBlindness(blindness);
                boolean snapshotPair = snapshot != null && snapshot.invulnerable && snapshot.noGravity;
                boolean flagResidue = player.isInvulnerable() && player.isNoGravity() && !snapshotPair;
                boolean signature = blindnessResidue || flagResidue;

                // Adventure residue: the sandbox switched the player to ADVENTURE at
                // quarantine. The truth source is the snapshot when one exists;
                // otherwise the auth-time game type remembered in the resume record.
                // Without a snapshot, only a corroborating signature justifies the
                // repair (the remembered value alone cannot distinguish a poisoned
                // save from a deliberate operator change).
                GameType current = player.gameMode.getGameModeForPlayer();
                GameType truth = snapshot != null ? snapshot.gameMode : session.resumedGameMode;
                if (current == GameType.ADVENTURE && truth != null && truth != GameType.ADVENTURE
                                && (snapshot != null || signature)) {
                        player.setGameMode(truth);
                        repaired = true;
                }

                if (blindnessResidue) {
                        clearBlindness(player);
                        repaired = true;
                }

                if (flagResidue) {
                        player.setInvulnerable(snapshot != null && snapshot.invulnerable);
                        player.setNoGravity(snapshot != null && snapshot.noGravity);
                        repaired = true;
                }

                if (repaired) {
                        // A player who just regained gravity may still carry fall distance
                        // accumulated in the sandbox; the repair itself must never hurt.
                        resetFallDistanceSafely(player);
                }
                return repaired;
        }

        /**
         * True when a blindness instance carries the exact signature the sandbox
         * applies (infinite duration, ambient, no particles). Only that instance
         * is ever removed by the reconciliation.
         */
        private static boolean isSandboxBlindness(MobEffectInstance effect) {
                try {
                        return effect.isAmbient() && !effect.isVisible() && effect.getDuration() < 0;
                } catch (RuntimeException ignored) {
                        return false;
                }
        }

        /** Best-effort fall-distance reset (API details vary across MC versions). */
        private static void resetFallDistanceSafely(ServerPlayer player) {
                try {
                        player.resetFallDistance();
                } catch (RuntimeException ignored) {
                        // Cosmetic best-effort; the damage hook covers the rest.
                }
        }

        // ------------------------------------------------------------------
        // Movement enforcement (server-side, continuous)
        // ------------------------------------------------------------------

        /**
         * Called every server tick: corrects unauthorised movement, dimension
         * escapes and clears stray entities from the auth area.
         */
        public void tick(AuthSession session) {
                if (session.authenticated()) {
                        return;
                }
                ServerPlayer player = session.player;

                // Position re-sync (since 1.2.2): while quarantined the server rejects all
                // client movement, so the client could otherwise keep a local prediction of
                // walking away. Ten times a second the authoritative platform position is
                // pushed back out, which visibly snaps any ghost movement home.
                MinecraftServer server = player.level().getServer();
                if (server != null && server.getTickCount() % 10 == 0
                                && session.authLevel != null && session.authSpawn != null) {
                        BlockPos spawn = session.authSpawn;
                        try {
                                player.connection.teleport(spawn.getX() + 0.5, spawn.getY() + 1.0,
                                                spawn.getZ() + 0.5, 0.0F, 0.0F);
                                player.setDeltaMovement(Vec3.ZERO);
                        } catch (RuntimeException ignored) {
                                // Re-sync is best-effort; the drift guard below still corrects.
                        }
                }

                // Blindness upkeep (once per second): re-apply the infinite effect so a
                // cleared effect (command, other mod) comes back within a second.
                if (server != null && server.getTickCount() % 20 == 0) {
                        applyBlindness(player);
                }

                if (!config.worldProtection.movementCorrection) {
                        return;
                }

                // Correct dimension escapes: the player must remain in the auth dimension.
                if (session.authLevel != null && player.level() != session.authLevel) {
                        logger.log(SecurityEvent.SANDBOX_ESCAPE_CORRECTED, session.usernameNorm, session.ip,
                                        "escaped_to=" + player.level().dimension().identifier());
                        quarantine(player, session);
                        return;
                }

                // Correct drifting off the platform (covers movement, velocity and
                // same-dimension teleports that slipped through other guards).
                if (session.authSpawn != null && session.authLevel != null) {
                        Vec3 pos = player.position();
                        double dx = pos.x - (session.authSpawn.getX() + 0.5);
                        double dz = pos.z - (session.authSpawn.getZ() + 0.5);
                        double dy = pos.y - session.authSpawn.getY();
                        double maxDrift = config.worldProtection.maxDriftBlocks;
                        if (dx * dx + dz * dz > maxDrift * maxDrift || Math.abs(dy) > maxDrift) {
                                BlockPos spawn = session.authSpawn;
                                teleport(player, session.authLevel, spawn.getX() + 0.5, spawn.getY() + 1.0,
                                                spawn.getZ() + 0.5, 0.0F, 0.0F);
                                player.setDeltaMovement(Vec3.ZERO);
                                logger.log(SecurityEvent.SANDBOX_ESCAPE_CORRECTED, session.usernameNorm, session.ip, "drift");
                        }
                }
        }

        /**
         * Quiet position repair for a player who is leaving while unauthenticated
         * and still inside the auth dimension (disconnect or timeout kick). Runs
         * BEFORE the disconnect save, so the recorded position lands in the real
         * world; a rejoin then spawns normally instead of inside the auth void.
         * The sandbox state (blindness, adventure, invulnerable, no-gravity) is
         * lifted before the save in BOTH isolation modes — none of it may ever
         * reach the player's save data. The position repair only applies to
         * players actually inside the auth dimension.
         */
        public void restoreOnDisconnect(ServerPlayer player, AuthSession session) {
                if (player == null) {
                        return;
                }
                boolean inAuthDimension = player.level().dimension() == AUTH_DIMENSION;
                OriginalLocation snapshot = session.originalLocation;
                // A real snapshot was captured BEFORE the sandbox switched the player to
                // adventure, so its game type is the trustworthy one. The respawn
                // fallback below is only for the position: it would capture the current
                // (sandbox) game type, so it must never be used to restore game mode.
                boolean realSnapshot = snapshot != null && snapshot.dimension != AUTH_DIMENSION;
                if (inAuthDimension && !realSnapshot) {
                        snapshot = respawnLocation(player);
                }
                OriginalLocation original = snapshot;
                if (inAuthDimension) {
                        MinecraftServer server = player.level().getServer();
                        ServerLevel target = original != null && server != null
                                        ? server.getLevel(original.dimension) : null;
                        if (target == null && server != null) {
                                target = server.overworld();
                        }
                        if (target != null && original != null) {
                                // 1.2.3: the disconnect repair no longer dimension-TELEPORTS.
                                // The play-disconnect event races the vanilla entity removal,
                                // and ServerPlayer.teleport silently no-ops for removed
                                // players — which could leave the auth dimension in the
                                // saved player data (flaky, once per few runs). The direct
                                // re-home below has no guard, sends no packets and touches
                                // no level bookkeeping: it deterministically fixes exactly
                                // what the imminent disconnect save writes (dimension,
                                // position, rotation). The entity stays registered in the
                                // auth level's storage until the vanilla teardown removes
                                // it through its own removal callback.
                                player.setServerLevel(target);
                                player.setPos(original.x, original.y, original.z);
                                player.setYRot(original.yaw);
                                player.setXRot(original.pitch);
                                player.setDeltaMovement(Vec3.ZERO);
                        }
                }
                // The disconnect save must not keep the quarantine sandbox state — in
                // EITHER isolation mode: the blindness is lifted and the original game
                // type restored before writing. Since 1.2.3 the sandbox's
                // invulnerable/no-gravity pair is reset too — leaving it set poisoned
                // the saved player data, so a rejoin loaded a permanently floating,
                // invulnerable player (the "/logout then rejoin then login = still
                // floating" report). The snapshot values are pre-quarantine (capture
                // happens before the sandbox applies them) and the respawn fallback
                // never carries them.
                clearBlindness(player);
                player.setGameMode(realSnapshot ? original.gameMode : GameType.SURVIVAL);
                player.setInvulnerable(original != null && original.invulnerable);
                player.setNoGravity(original != null && original.noGravity);
        }

        /**
         * The position a stuck player should be returned to when the real snapshot
         * is unavailable: their respawn anchor (bed/respawn block) when one is set,
         * otherwise the overworld spawn. Never returns a position inside the auth
         * dimension.
         */
        private OriginalLocation respawnLocation(ServerPlayer player) {
                MinecraftServer server = player.level().getServer();
                ServerLevel target = null;
                BlockPos pos = null;
                try {
                        ServerPlayer.RespawnConfig config = player.getRespawnConfig();
                        LevelData.RespawnData data = config != null ? config.respawnData() : null;
                        if (data != null && data.pos() != null && server != null) {
                                ServerLevel candidate = server.getLevel(data.dimension());
                                if (candidate != null && candidate.dimension() != AUTH_DIMENSION) {
                                        target = candidate;
                                        pos = data.pos();
                                }
                        }
                } catch (RuntimeException ignored) {
                        // Fall through to the overworld spawn.
                }
                if (target == null || pos == null) {
                        target = server != null ? server.overworld() : (ServerLevel) player.level();
                        pos = fallbackSpawn(target);
                }
                return OriginalLocation.respawn(target.dimension(), pos.getX() + 0.5, pos.getY(), pos.getZ() + 0.5,
                                player);
        }

        /** Removes non-player entities that somehow ended up in the auth dimension. */
        public void sweepAuthEntities(MinecraftServer server) {
                if (!config.worldProtection.clearAuthEntities) {
                        return;
                }
                ServerLevel level = authLevel(server);
                if (level == null) {
                        return;
                }
                for (Entity entity : level.getAllEntities()) {
                        if (!(entity instanceof ServerPlayer)) {
                                entity.discard();
                        }
                }
        }

        // ------------------------------------------------------------------
        // Void purity (continuous, self-healing)
        // ------------------------------------------------------------------

        /**
         * Removes every block of the auth dimension that is not part of the stone
         * platform, from every currently loaded chunk, working outwards from the
         * platform. This is the self-healing layer of the pure-void contract: it
         * cleans up water, lava, terrain and other leftovers from legacy generators,
         * other mods or operator accidents within seconds, and it costs nothing once
         * the dimension is clean (empty sections are skipped in palette time).
         *
         * <p>Runs once per second from the auth manager housekeeping when
         * {@code worldProtection.pureVoid} is enabled (default). A removal budget per
         * pass keeps a single tick cheap even while a large legacy area is being
         * cleaned; the sweep simply continues where it stopped on the next pass.</p>
         */
        public void purifyVoid(MinecraftServer server) {
                if (!config.worldProtection.pureVoid) {
                        return;
                }
                ServerLevel level = authLevel(server);
                if (level == null) {
                        return;
                }

                int scanRadius = 8;
                try {
                        scanRadius = Math.min(16, Math.max(8, server.getPlayerList().getViewDistance() + 2));
                } catch (RuntimeException ignored) {
                        // Keep the conservative default radius.
                }

                int removed = 0;
                int probed = 0;
                int loaded = 0;
                // Ring order: the chunks a quarantined player actually sees first clean up
                // first even when a large legacy area is still being processed.
                for (int ring = 0; ring <= scanRadius && removed < PURIFY_BUDGET; ring++) {
                        for (int dx = -ring; dx <= ring && removed < PURIFY_BUDGET; dx++) {
                                for (int dz = -ring; dz <= ring && removed < PURIFY_BUDGET; dz++) {
                                        if (Math.max(Math.abs(dx), Math.abs(dz)) != ring) {
                                                continue; // only the current ring
                                        }
                                        probed++;
                                        LevelChunk chunk = level.getChunkSource().getChunkNow(dx, dz);
                                        if (chunk == null) {
                                                continue; // not loaded: nothing to clean, nothing to see
                                        }
                                        loaded++;
                                        removed += purgeChunk(level, chunk, PURIFY_BUDGET - removed);
                                }
                        }
                }
                if (PURIFY_DEBUG.incrementAndGet() <= 12) {
                        org.slf4j.LoggerFactory.getLogger("secureauth").info(
                                        "void purifier sweep #{}: probed={} loaded={} removed={}",
                                        PURIFY_DEBUG.get(), probed, loaded, removed);
                }
                if (removed > 0) {
                        long now = System.currentTimeMillis();
                        if (now - lastPurifyLogAt >= PURIFY_LOG_INTERVAL_MS) {
                                lastPurifyLogAt = now;
                                logger.log(SecurityEvent.SANDBOX_ESCAPE_CORRECTED, "void-purifier", null,
                                                "", "removed " + removed + " stray block(s); pure void restored");
                        }
                }
        }

        /**
         * Clears one loaded chunk of every block that is not part of the holding
         * cell. Sections whose palette contains only air are skipped in palette
         * time, so a clean dimension costs a handful of probes per chunk; any
         * non-air palette entry forces a position-aware scan because the palette
         * cannot tell where the blocks sit. Since 1.2.4 the allowed set is the
         * full cell shell (floor + walls + ceiling) — the purifier and the cell
         * builder share {@link #isHoldingCellBlock}, so the box can never be
         * mistaken for junk (or the junk for the box).
         */
        private int purgeChunk(ServerLevel level, LevelChunk chunk, int budget) {
                int removed = 0;
                int baseX = chunk.getPos().x() << 4;
                int baseZ = chunk.getPos().z() << 4;
                LevelChunkSection[] sections = chunk.getSections();
                for (int i = 0; i < sections.length && removed < budget; i++) {
                        LevelChunkSection section = sections[i];
                        if (section == null || section.hasOnlyAir()) {
                                continue;
                        }
                        int sectionBaseY = chunk.getMinY() + (i << 4);
                        if (!section.maybeHas(state -> !state.isAir())) {
                                continue;
                        }
                        for (int y = 0; y < 16 && removed < budget; y++) {
                                int worldY = sectionBaseY + y;
                                for (int x = 0; x < 16 && removed < budget; x++) {
                                        int worldX = baseX + x;
                                        for (int z = 0; z < 16 && removed < budget; z++) {
                                                if (section.getBlockState(x, y, z).isAir()) {
                                                        continue;
                                                }
                                                int worldZ = baseZ + z;
                                                if (isHoldingCellBlock(worldX, worldY, worldZ)) {
                                                        continue;
                                                }
                                                level.setBlock(new BlockPos(worldX, worldY, worldZ),
                                                                Blocks.AIR.defaultBlockState(), Block.UPDATE_ALL);
                                                removed++;
                                        }
                                }
                        }
                }
                return removed;
        }

        /** Resolves a safe overworld spawn position for the defensive fallback. */
        private BlockPos fallbackSpawn(ServerLevel overworld) {
                try {
                        net.minecraft.world.level.storage.LevelData.RespawnData respawn = overworld.getLevelData().getRespawnData();
                        if (respawn != null && respawn.pos() != null) {
                                return respawn.pos();
                        }
                } catch (Exception ignored) {
                        // fall through
                }
                return new BlockPos(0, 100, 0);
        }

        // ------------------------------------------------------------------
        // Holding cell (platform + optional bedrock shell)
        // ------------------------------------------------------------------

        /** Interior height of the holding cell (3 blocks: jump room, no suffocation). */
        private static final int CELL_INTERIOR_HEIGHT = 3;

        /**
         * Ensures the holding cell exists and returns its centre block. Since 1.2.4
         * the cell is a sealed bedrock box when {@code worldProtection.platformBox}
         * is enabled (default): a {@code platformRadius}-half-extent interior with
         * a floor of {@code platformBlock} (bedrock by default), unbreakable bedrock
         * walls one block further out and a bedrock ceiling three rows above the
         * floor. A player inside can jump, look around and wait — but never fall
         * off, never fall out and never suffocate: the worst outcome of any
         * release failure is "waiting inside a sealed cell", exactly as requested.
         */
        private BlockPos ensurePlatform(ServerLevel level) {
                int radius = config.worldProtection.platformRadius;
                int y = config.worldProtection.platformY;
                BlockState floor = platformBlockState();
                BlockState shell = Blocks.BEDROCK.defaultBlockState();
                boolean box = config.worldProtection.platformBox;
                int shellRadius = radius + 1;
                BlockPos centre = new BlockPos(0, y, 0);
                boolean changed = false;
                for (int dy = 0; dy <= (box ? CELL_INTERIOR_HEIGHT + 1 : 0); dy++) {
                        for (int dx = -shellRadius; dx <= shellRadius; dx++) {
                                for (int dz = -shellRadius; dz <= shellRadius; dz++) {
                                        if (!isHoldingCellBlock(dx, y + dy, dz)) {
                                                continue;
                                        }
                                        BlockState wanted = (dy == 0 || !box) ? floor : shell;
                                        BlockPos pos = new BlockPos(centre.getX() + dx, y + dy, centre.getZ() + dz);
                                        // Replace anything that is not the intended cell block: air,
                                        // liquids, and stray solids left behind by legacy generators.
                                        if (level.getBlockState(pos).getBlock() != wanted.getBlock()) {
                                                level.setBlockAndUpdate(pos, wanted);
                                                changed = true;
                                        }
                                }
                        }
                }
                if (changed && !platformWarned) {
                        platformWarned = true;
                }
                return centre;
        }

        /**
         * The single source of truth for the shape of the holding cell: true for
         * every block position that BELONGS to the cell (floor, walls, ceiling).
         * Both the builder and the void purifier use it, so the purifier can
         * never eat the cell it is supposed to keep.
         *
         * <p>With the box enabled (default) the allowed set is the sealed shell:
         * the full footprint on the floor row and the ceiling row, plus the wall
         * ring on every row in between. With {@code platformBox=false} it is the
         * legacy flat platform ({@code platformRadius} half-extent on one row).
         * The interior is air and never part of the allowed set.</p>
         */
        private boolean isHoldingCellBlock(int x, int y, int z) {
                int baseY = config.worldProtection.platformY;
                int radius = config.worldProtection.platformRadius;
                if (!config.worldProtection.platformBox) {
                        return y == baseY && Math.abs(x) <= radius && Math.abs(z) <= radius;
                }
                int shellRadius = radius + 1;
                if (y < baseY || y > baseY + CELL_INTERIOR_HEIGHT + 1) {
                        return false;
                }
                if (Math.abs(x) > shellRadius || Math.abs(z) > shellRadius) {
                        return false;
                }
                return y == baseY || y == baseY + CELL_INTERIOR_HEIGHT + 1
                                || Math.abs(x) == shellRadius || Math.abs(z) == shellRadius;
        }

        private BlockState platformBlockState() {
                try {
                        Identifier id = Identifier.parse(config.worldProtection.platformBlock);
                        Optional<Block> block = BuiltInRegistries.BLOCK.getOptional(id);
                        if (block.isPresent()) {
                                return block.get().defaultBlockState();
                        }
                } catch (Exception ignored) {
                        // fall through to default
                }
                return Blocks.BEDROCK.defaultBlockState();
        }

        // ------------------------------------------------------------------
        // Sandbox sensory isolation (since 1.2.2)
        // ------------------------------------------------------------------

        /**
         * Applies the infinite blindness effect to a quarantined player (unless
         * {@code worldProtection.quarantineBlindness} is disabled). Blindness
         * thickens the fog to a few blocks, so whatever a modified client could
         * still render of the dimension (far geometry, legacy junk below the
         * platform, particles) is simply not visible. The effect is ambient and
         * particle-free; the client cannot dismiss it because effects are
         * server-authoritative, and the once-per-second upkeep in
         * {@link #tick(AuthSession)} restores it even after a clearing command.
         */
        private void applyBlindness(ServerPlayer player) {
                if (!config.worldProtection.quarantineBlindness) {
                        return;
                }
                try {
                        player.addEffect(new MobEffectInstance(MobEffects.BLINDNESS,
                                        MobEffectInstance.INFINITE_DURATION, 0, true, false, false));
                } catch (RuntimeException ignored) {
                        // Effect application is best-effort; the dimension does the real isolation.
                }
        }

        /** Removes the quarantine blindness effect (restores, disconnect, timeout). */
        private void clearBlindness(ServerPlayer player) {
                try {
                        player.removeEffect(MobEffects.BLINDNESS);
                } catch (RuntimeException ignored) {
                        // Removal is best-effort.
                }
        }

        // ------------------------------------------------------------------
        // Teleport helper (single adaptation point for the 26.2 teleport API)
        // ------------------------------------------------------------------

        private void teleport(ServerPlayer player, ServerLevel level, double x, double y, double z, float yaw, float pitch) {
                clearStaleRemovalFlag(player);
                player.teleport(new TeleportTransition(level, new Vec3(x, y, z), Vec3.ZERO, yaw, pitch,
                                TeleportTransition.DO_NOTHING));
        }

        /**
         * Clears a stale {@code removed} flag left by a half-finished dimension
         * transfer (since 1.2.4). {@code ServerPlayer.teleport()} hard-returns for
         * removed entities, so a player whose release transfer failed mid-way under
         * lag would silently no-op EVERY later teleport — the exact "stuck in the
         * auth dimension after a laggy login" report. The flag is only cleared for
         * the live entity of a still-connected session (the connection still points
         * at it), mirroring what vanilla itself does mid-transfer.
         */
        private static void clearStaleRemovalFlag(ServerPlayer player) {
                if (!player.isRemoved()) {
                        return;
                }
                try {
                        if (player.connection != null && player.connection.player == player) {
                                ((net.secureauth.mixin.EntityMixin) player).secureauth$unsetRemoved();
                        }
                } catch (RuntimeException ignored) {
                        // Best effort; the teleport below simply stays a no-op for this tick.
                }
        }

        /** Disconnects a player with a fully resolved (literal) reason component. */
        public static void disconnect(ServerPlayer player, Component reason) {
                player.connection.disconnect(reason);
        }
}
