package net.secureauth.world;

import net.minecraft.resources.ResourceKey;
import net.minecraft.server.level.ServerPlayer;
import net.minecraft.world.level.GameType;
import net.minecraft.world.level.Level;

/**
 * Snapshot of where and how the player was when they joined, taken BEFORE
 * moving them into the authentication area. All values are read server-side;
 * client-provided data is never used. Restored verbatim after authentication.
 */
public final class OriginalLocation {

        public final ResourceKey<Level> dimension;
        public final double x;
        public final double y;
        public final double z;
        public final float yaw;
        public final float pitch;
        public final GameType gameMode;
        public final boolean invulnerable;
        public final boolean noGravity;

        private OriginalLocation(ResourceKey<Level> dimension, double x, double y, double z,
                        float yaw, float pitch, GameType gameMode, boolean invulnerable, boolean noGravity) {
                this.dimension = dimension;
                this.x = x;
                this.y = y;
                this.z = z;
                this.yaw = yaw;
                this.pitch = pitch;
                this.gameMode = gameMode;
                this.invulnerable = invulnerable;
                this.noGravity = noGravity;
        }

        /** Captures the player's authoritative server-side state. */
        public static OriginalLocation capture(ServerPlayer player) {
                return new OriginalLocation(
                                player.level().dimension(),
                                player.getX(), player.getY(), player.getZ(),
                                player.getYRot(), player.getXRot(),
                                player.gameMode.getGameModeForPlayer(),
                                player.isInvulnerable(),
                                player.isNoGravity());
        }

        /**
         * Builds a fallback snapshot for a player whose real position lies inside
         * the auth dimension (rejoin after a timeout/quit while quarantined): the
         * auth area must never become the restored "original location".
         *
         * <p>Since 1.2.3 the flags are hard-coded to {@code false}: this fallback
         * is only built for a player who is currently quarantined, whose live
         * invulnerable/no-gravity flags ARE the sandbox flags — copying them
         * would restore a permanently floating, invulnerable player after login.</p>
         */
        static OriginalLocation respawn(ResourceKey<Level> dimension, double x, double y, double z,
                        ServerPlayer player) {
                return new OriginalLocation(dimension, x, y, z, 0.0F, 0.0F,
                                player.gameMode.getGameModeForPlayer(), false, false);
        }

        /**
         * Returns a copy with the quarantine signature (invulnerable AND
         * no-gravity — the exact pair the sandbox applies) cleared. A player who
         * rejoins with that pair saved is carrying leftover sandbox state from a
         * pre-1.2.3 disconnect (the flags used to be written into the player's
         * save data); restoring them would keep the player floating and
         * invulnerable after login. A player who genuinely plays with both flags
         * set at once loses them once, at the next login.
         */
        static OriginalLocation repairSandboxResidue(OriginalLocation snapshot) {
                if (snapshot == null || !(snapshot.invulnerable && snapshot.noGravity)) {
                        return snapshot;
                }
                return new OriginalLocation(snapshot.dimension, snapshot.x, snapshot.y, snapshot.z,
                                snapshot.yaw, snapshot.pitch, snapshot.gameMode, false, false);
        }
}
