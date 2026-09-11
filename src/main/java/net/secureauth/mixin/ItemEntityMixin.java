package net.secureauth.mixin;

import net.minecraft.server.level.ServerPlayer;
import net.minecraft.world.entity.item.ItemEntity;
import net.minecraft.world.entity.player.Player;
import net.secureauth.SecureAuth;
import net.secureauth.auth.AuthManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Unique;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

/**
 * Item-pickup guard for the pre-authentication sandbox (fail closed).
 *
 * <p><b>What it blocks and why.</b> {@code playerTouch(Player)} is the single
 * vanilla entry point through which a player collects a dropped
 * {@link ItemEntity} (verified on the 26.2 game-server jar: public, returns
 * {@code void}, descriptor {@code playerTouch(Lnet/minecraft/world/entity/player/Player;)V}).
 * While the touching player is unauthenticated the pickup is cancelled at
 * HEAD: unauthenticated players can neither loot the auth area nor hoover up
 * items dropped by other players near the quarantine boundary. Cancelling the
 * method entirely also skips the pickup delay bookkeeping, so the entity
 * stays available for legitimately authenticated players.</p>
 *
 * <p><b>Fail closed.</b> Only {@link ServerPlayer} instances are checked
 * (client-side copies of the level never present a server player, so the
 * mixin is inert on the client even in a shared singleplayer JVM). The state
 * comes from {@link AuthManager#isAuthenticated(ServerPlayer)}, which treats
 * a missing session as unauthenticated. When the mod is absent, disabled, or
 * its manager is shut down, pickups behave exactly like vanilla. No feedback
 * is sent: item pickup is not a deliberate player action, and the touch path
 * runs every tick for nearby entities.</p>
 *
 * <p><b>Failure policy.</b> No exception ever escapes into the entity tick.
 * An unexpected internal error fails closed (pickup cancelled) with a debug
 * log — item flow into an unauthenticated inventory is part of the sandbox
 * boundary.</p>
 */
@Mixin(ItemEntity.class)
public abstract class ItemEntityMixin {

	/** Debug-only logger for unexpected internal states (never the security log). */
	@Unique
	private static final Logger SECUREAUTH_LOG = LoggerFactory.getLogger("secureauth.mixin");

	@Inject(method = "playerTouch(Lnet/minecraft/world/entity/player/Player;)V",
			at = @At("HEAD"), cancellable = true)
	private void secureauth$onPlayerTouch(Player player, CallbackInfo ci) {
		try {
			if (!(player instanceof ServerPlayer serverPlayer)) {
				// Client-side touch or non-player: vanilla behaviour.
				return;
			}
			SecureAuth self = SecureAuth.get();
			if (self == null || !self.enabled()) {
				return;
			}
			AuthManager manager = self.authManager();
			if (manager == null) {
				return;
			}
			if (!manager.isAuthenticated(serverPlayer)) {
				// void method: plain cancellation stops the pickup entirely.
				ci.cancel();
			}
		} catch (Throwable t) {
			SECUREAUTH_LOG.debug("SecureAuth item-pickup guard error; pickup blocked", t);
			ci.cancel();
		}
	}
}
