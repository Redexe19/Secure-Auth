package net.secureauth.mixin;

import net.minecraft.server.level.ServerLevel;
import net.minecraft.server.level.ServerPlayer;
import net.minecraft.world.entity.Entity;
import net.secureauth.SecureAuth;
import net.secureauth.world.AuthWorldManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfoReturnable;

/**
 * Entity-birth guard for the authentication dimension (fail closed).
 *
 * <p><b>What it blocks and why.</b> {@code addFreshEntity(Entity)} is the single
 * public vanilla entry point through which every server-side entity enters a
 * {@link ServerLevel} (natural mob spawns, insomnia phantoms, wandering traders,
 * dropped items, projectiles, TNT, falling blocks, mod-spawned creatures…).
 * The auth dimension must contain nothing but quarantined players and their
 * stone platform, so any non-player entity addition to {@code secureauth:auth}
 * is rejected at HEAD and the caller sees the same result as a refused spawn
 * ({@code false}). Entities already saved inside legacy chunk files are removed
 * separately by the periodic sweep in {@link AuthWorldManager}.</p>
 *
 * <p><b>Fail closed.</b> The static guard flag defaults to {@code true}, so even
 * a partially initialised mod refuses entities in the auth dimension. When the
 * mod is fully disabled ({@code authentication.enabled=false}) or the user opts
 * out via {@code worldProtection.clearAuthEntities=false}, the mixin passes
 * straight through and the dimension behaves like any vanilla level. Players
 * are always allowed — they are the whole point of the dimension.</p>
 *
 * <p><b>Failure policy.</b> No exception ever escapes into the entity-add path;
 * an unexpected internal error fails closed (entity refused) with a debug log.</p>
 */
@Mixin(ServerLevel.class)
public abstract class ServerLevelMixin {

        /** Debug-only logger for unexpected internal states (never the security log). */
        private static final Logger SECUREAUTH_LOG = LoggerFactory.getLogger("secureauth.mixin");

        @Inject(method = "addFreshEntity(Lnet/minecraft/world/entity/Entity;)Z",
                        at = @At("HEAD"), cancellable = true)
        private void secureauth$rejectEntitiesInAuthDimension(Entity entity, CallbackInfoReturnable<Boolean> cir) {
                try {
                        if (entity instanceof ServerPlayer) {
                                // Players are the only legitimate inhabitants.
                                return;
                        }
                        ServerLevel self = (ServerLevel) (Object) this;
                        if (self.dimension() != AuthWorldManager.AUTH_DIMENSION) {
                                return;
                        }
                        SecureAuth mod = SecureAuth.get();
                        if (mod == null || !mod.enabled()) {
                                // Mod disabled: pass through, consistent with every other guard.
                                return;
                        }
                        if (AuthWorldManager.entityGuard()) {
                                cir.setReturnValue(false);
                        }
                } catch (Throwable t) {
                        SECUREAUTH_LOG.debug("SecureAuth entity-birth guard error; entity refused", t);
                        cir.setReturnValue(false);
                }
        }
}
