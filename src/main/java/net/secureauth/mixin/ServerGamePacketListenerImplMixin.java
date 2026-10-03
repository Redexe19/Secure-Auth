package net.secureauth.mixin;

import net.minecraft.network.protocol.game.ServerboundContainerClickPacket;
import net.minecraft.network.protocol.game.ServerboundMovePlayerPacket;
import net.minecraft.network.protocol.game.ServerboundMoveVehiclePacket;
import net.minecraft.network.protocol.game.ServerboundPlayerActionPacket;
import net.minecraft.server.level.ServerPlayer;
import net.minecraft.server.network.ServerGamePacketListenerImpl;
import net.secureauth.SecureAuth;
import net.secureauth.auth.AuthManager;
import net.secureauth.ui.ChestGui;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.Unique;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

/**
 * Movement, player-action and container-click guards for the pre-authentication
 * sandbox (fail closed).
 *
 * <p><b>What it blocks and why.</b> While the player is unauthenticated the
 * following serverbound handlers are cancelled at HEAD, before any vanilla
 * logic observes the packet:</p>
 * <ul>
 *   <li>{@code handleMovePlayer(ServerboundMovePlayerPacket)} — the vanilla
 *       handler must not run so the server-side position never follows client
 *       input; the authoritative correction (teleport back to the platform /
 *       into the auth dimension) is performed every tick by
 *       {@code AuthManager.tick} / {@code AuthWorldManager.tick}. Server-to-
 *       client position corrections are outgoing packets and remain fully
 *       functional.</li>
 *   <li>{@code handleMoveVehicle(ServerboundMoveVehiclePacket)} — hardening:
 *       a modified client could otherwise move the (passenger) player
 *       server-side by steering a vehicle.</li>
 *   <li>{@code handlePlayerAction(ServerboundPlayerActionPacket)} — blocks
 *       block digging (start/stop/abort destroy), item dropping (Q / Ctrl+Q),
 *       hand swapping and item-use release inside the sandbox.</li>
 *   <li>{@code handleContainerClick(ServerboundContainerClickPacket)} —
 *       blocks every inventory and container click (moving, shift-moving,
 *       swapping, dropping, crafting, chest/Ender Chest interaction).
 *       <b>Exception:</b> clicks arriving while the player has a SecureAuth
 *       chest menu open ({@link ChestGui} — the auth/admin panels) are let
 *       through: those menus intercept every click themselves (never moving
 *       a real item) and their button items are the authentication UX.
 *       Letting only {@code ChestGui} types through cannot leak a real chest
 *       interaction, because a {@code ChestGui} menu never applies any click
 *       to the underlying container.</li>
 * </ul>
 *
 * <p><b>Verified targets</b> (minijavap on the 26.2 game-server jar): all four
 * methods are public, return {@code void}, and have the exact descriptors
 * {@code handleMovePlayer(Lnet/minecraft/network/protocol/game/ServerboundMovePlayerPacket;)V},
 * {@code handleMoveVehicle(Lnet/minecraft/network/protocol/game/ServerboundMoveVehiclePacket;)V},
 * {@code handlePlayerAction(Lnet/minecraft/network/protocol/game/ServerboundPlayerActionPacket;)V}
 * and {@code handleContainerClick(Lnet/minecraft/network/protocol/game/ServerboundContainerClickPacket;)V}.
 * The {@code player} field is shadowed exactly as declared in the target:
 * {@code public ServerPlayer player} (public, non-static, non-final).
 * Cancellation uses {@code ci.cancel()} — every target returns {@code void}.</p>
 *
 * <p><b>Fail closed.</b> The gate consults
 * {@link AuthManager#isAuthenticated(ServerPlayer)}, which returns
 * {@code false} for a missing session — a player the mod never quarantined
 * (e.g. a race between the play-phase switch and the JOIN event) is treated
 * as unauthenticated and blocked, never trusted. When the mod is absent,
 * disabled, or its manager is shut down, the guards pass through and vanilla
 * behaviour is untouched. Guards are silent by design: movement arrives many
 * times per second, and interactive feedback (throttled
 * {@code auth.interaction.blocked} notices plus sandbox-escape logging) is
 * already provided by the Fabric event guards in {@code SecureAuth}.</p>
 *
 * <p><b>Failure policy.</b> No exception ever escapes into the vanilla packet
 * handlers. An unexpected internal error fails closed (the packet is
 * cancelled) with a debug log, because these guards ARE the security
 * boundary.</p>
 */
@Mixin(ServerGamePacketListenerImpl.class)
public abstract class ServerGamePacketListenerImplMixin {

        /** Debug-only logger for unexpected internal states (never the security log). */
        @Unique
        private static final Logger SECUREAUTH_LOG = LoggerFactory.getLogger("secureauth.mixin");

        /** Mirrors the target's {@code public ServerPlayer player} field exactly. */
        @Shadow
        public ServerPlayer player;

        @Inject(method = "handleMovePlayer(Lnet/minecraft/network/protocol/game/ServerboundMovePlayerPacket;)V",
                        at = @At("HEAD"), cancellable = true)
        private void secureauth$onMovePlayer(ServerboundMovePlayerPacket packet, CallbackInfo ci) {
                secureauth$blockIfUnauthenticated(ci);
        }

        @Inject(method = "handleMoveVehicle(Lnet/minecraft/network/protocol/game/ServerboundMoveVehiclePacket;)V",
                        at = @At("HEAD"), cancellable = true)
        private void secureauth$onMoveVehicle(ServerboundMoveVehiclePacket packet, CallbackInfo ci) {
                secureauth$blockIfUnauthenticated(ci);
        }

        @Inject(method = "handlePlayerAction(Lnet/minecraft/network/protocol/game/ServerboundPlayerActionPacket;)V",
                        at = @At("HEAD"), cancellable = true)
        private void secureauth$onPlayerAction(ServerboundPlayerActionPacket packet, CallbackInfo ci) {
                secureauth$blockIfUnauthenticated(ci);
        }

        @Inject(method = "handleContainerClick(Lnet/minecraft/network/protocol/game/ServerboundContainerClickPacket;)V",
                        at = @At("HEAD"), cancellable = true)
        private void secureauth$onContainerClick(ServerboundContainerClickPacket packet, CallbackInfo ci) {
                secureauth$blockIfUnauthenticatedUnlessPanel(ci);
        }

        /**
         * Cancels the vanilla handler when this connection's player is not
         * authenticated. Fail closed: no session counts as unauthenticated. Never
         * throws; unexpected internal errors also cancel (this is the hard
         * boundary), logged at debug level only.
         */
        private void secureauth$blockIfUnauthenticated(CallbackInfo ci) {
                try {
                        SecureAuth self = SecureAuth.get();
                        if (self == null || !self.enabled()) {
                                return;
                        }
                        AuthManager manager = self.authManager();
                        if (manager == null) {
                                return;
                        }
                        ServerPlayer player = this.player;
                        if (player == null) {
                                return;
                        }
                        if (manager.isAuthenticated(player)) {
                                return;
                        }
                        ci.cancel();
                } catch (Throwable t) {
                        SECUREAUTH_LOG.debug("SecureAuth packet guard error; packet blocked", t);
                        ci.cancel();
                }
        }

        /**
         * Same gate as {@link #secureauth$blockIfUnauthenticated(CallbackInfo)},
         * but a click inside one of SecureAuth's own chest menus is allowed
         * through: the unauthenticated player's auth panel IS the intended
         * interaction surface, and a {@link ChestGui} never moves a real item.
         */
        private void secureauth$blockIfUnauthenticatedUnlessPanel(CallbackInfo ci) {
                try {
                        SecureAuth self = SecureAuth.get();
                        if (self == null || !self.enabled()) {
                                return;
                        }
                        AuthManager manager = self.authManager();
                        if (manager == null) {
                                return;
                        }
                        ServerPlayer player = this.player;
                        if (player == null) {
                                return;
                        }
                        if (manager.isAuthenticated(player)) {
                                return;
                        }
                        if (player.containerMenu instanceof ChestGui) {
                                // Clicks in the auth/admin chest panels are handled by the
                                // menu itself; the vanilla handler would only be a passthrough.
                                return;
                        }
                        ci.cancel();
                } catch (Throwable t) {
                        SECUREAUTH_LOG.debug("SecureAuth packet guard error; packet blocked", t);
                        ci.cancel();
                }
        }
}
