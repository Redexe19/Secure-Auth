package net.secureauth.mixin;

import java.util.List;
import java.util.concurrent.Executor;
import com.llamalad7.mixinextras.injector.wrapoperation.Operation;
import com.llamalad7.mixinextras.injector.wrapoperation.WrapOperation;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.level.ServerLevel;
import net.minecraft.resources.ResourceKey;
import net.minecraft.world.level.CustomSpawner;
import net.minecraft.world.level.Level;
import net.minecraft.world.level.dimension.LevelStem;
import net.minecraft.world.level.storage.LevelStorageSource;
import net.minecraft.world.level.storage.ServerLevelData;
import net.secureauth.SecureAuth;
import net.secureauth.world.AuthWorldManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;

/**
 * Independent per-boot seed for the authentication dimension (since 1.2.2).
 *
 * <p><b>What it does and why.</b> Vanilla derives the seed of every datapack
 * dimension from the single world seed stored in {@code level.dat}, so all
 * dimensions of a world share one seed. The auth dimension must never be
 * correlated with the overworld, nether or end in any way, and every server
 * restart regenerates it from scratch (the start-of-boot chunk wipe in
 * {@code SecureAuth}). This mixin wraps the single {@code new ServerLevel(...)}
 * call site of {@code MinecraftServer.createLevels} — used for the overworld
 * and for every datapack dimension alike — and, when the dimension being
 * created is {@code secureauth:auth}, substitutes a freshly generated
 * cryptographically random seed. Every other dimension (and the overworld)
 * keeps its original seed; when the mod is disabled the call is an untouched
 * pass-through.</p>
 *
 * <p><b>Implementation note.</b> The {@code long} seed argument of the
 * {@code ServerLevel} constructor flows into the level's {@code BiomeManager}
 * (via the {@code Level} super constructor) and the generator state; for the
 * flat-air void generator the seed has no effect on the generated blocks —
 * which is exactly why re-seeding is free: the contract "a fresh, uncorrelated
 * dimension every boot" holds without any risk to generation. MixinExtras
 * {@code @WrapOperation} is provided by the fabric loader itself (bundled
 * MixinExtras 0.5.5), so the mod needs no additional dependency.</p>
 *
 * <p><b>Failure policy.</b> Any unexpected error falls back to the original
 * seed (the wrap must never break server boot); the wipe + runtime purifier
 * keep the pure-void guarantee regardless of the seed.</p>
 */
@Mixin(MinecraftServer.class)
public abstract class MinecraftServerMixin {

        /** Init-level logger for the one-line re-seed notice (visible for admins). */
        private static final Logger SECUREAUTH_LOG = LoggerFactory.getLogger("secureauth");

        @WrapOperation(
                        method = "createLevels",
                        at = @At(value = "NEW",
                                        target = "(Lnet/minecraft/server/MinecraftServer;Ljava/util/concurrent/Executor;"
                                                        + "Lnet/minecraft/world/level/storage/LevelStorageSource$LevelStorageAccess;"
                                                        + "Lnet/minecraft/world/level/storage/ServerLevelData;"
                                                        + "Lnet/minecraft/resources/ResourceKey;"
                                                        + "Lnet/minecraft/world/level/dimension/LevelStem;ZJ"
                                                        + "Ljava/util/List;Z)Lnet/minecraft/server/level/ServerLevel;"))
        private ServerLevel secureauth$reseedAuthDimension(MinecraftServer server, Executor executor,
                        LevelStorageSource.LevelStorageAccess access, ServerLevelData levelData,
                        ResourceKey<Level> dimension, LevelStem stem, boolean debugWorld, long seed,
                        List<CustomSpawner> customSpawners, boolean tickTime,
                        Operation<ServerLevel> original) {
                try {
                        SecureAuth mod = SecureAuth.get();
                        if (mod != null && mod.enabled()
                                        && dimension == AuthWorldManager.AUTH_DIMENSION
                                        && mod.config().worldProtection.resetOnRestart) {
                                long freshSeed = new java.security.SecureRandom().nextLong();
                                SECUREAUTH_LOG.info("SecureAuth: auth dimension re-seeded with a fresh random "
                                                + "seed ({}) — uncorrelated with the overworld, nether and end, "
                                                + "and different on every server restart.", freshSeed);
                                return original.call(server, executor, access, levelData, dimension, stem,
                                                debugWorld, freshSeed, customSpawners, tickTime);
                        }
                } catch (Throwable t) {
                        SECUREAUTH_LOG.debug("SecureAuth re-seed wrap error; keeping the original seed", t);
                }
                return original.call(server, executor, access, levelData, dimension, stem,
                                debugWorld, seed, customSpawners, tickTime);
        }
}
