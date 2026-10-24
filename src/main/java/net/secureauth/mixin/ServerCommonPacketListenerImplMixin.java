package net.secureauth.mixin;

import io.netty.channel.ChannelFutureListener;
import net.minecraft.network.protocol.Packet;
import net.minecraft.server.network.ServerCommonPacketListenerImpl;
import net.minecraft.server.network.ServerGamePacketListenerImpl;
import net.secureauth.SecureAuth;
import net.secureauth.auth.AuthManager;
import net.secureauth.network.PacketBypass;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Unique;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

/**
 * Outgoing world-information filter for unauthenticated viewers.
 * What it blocks.
 * Both send overloads of the common packet listener are intercepted at HEAD; when shouldDrop decides
 * the packet would leak real-world information to a specific unauthenticated viewer (other players'
 * tab-list entries, chat broadcasts, maps, optionally scoreboards and custom payloads), the send is
 * cancelled and the packet never reaches the connection.
 * SecureAuth's own packets (auth prompts, the tab-list hiding packets, ...) are exempt via
 * isBypassed.
 * Because both targets return void, cancellation uses ci.cancel (plain CallbackInfo; there is no
 * setReturnValue on it).
 * Fail-open by design — and why that is safe here.
 * This filter is information isolation, not the security boundary: it only hides cosmetic world data.
 * shouldDrop itself returns "pass" when the viewer has no session or is authenticated, and this mixin
 * deliberately mirrors that behaviour instead of pre-checking the session: a missing session means the
 * mod never quarantined this player (the player joined while the mod was inert/disabled, or the
 * listener is not a game-phase listener at all), so there is no quarantine whose information
 * boundaries could be violated.
 * The actual fail-closed boundary — no movement, no actions, no commands, no item pickup without
 * authentication — is enforced by the other three mixins and by
 * AuthManager.tick/AuthWorldManager.tick.
 * Nothing is logged from this hot path (it runs for every outgoing packet) to avoid spam.
 * Guard order (all null-safe, no exceptions ever escape): isBypassed — SecureAuth's own sends pass.
 * get null or enabled == false — inert mod. authManager == null — disabled/shutting-down mod.
 * (Object)this instanceof ServerGamePacketListenerImpl — only the play phase carries world
 * information; configuration/login listeners pass. shouldDrop decides (it re-checks bypass, listener
 * type, player, session state and the config switches).
 * Unexpected internal errors are caught, logged at debug level and treated as "pass": an error in the
 * isolation layer must never break packet delivery for everyone; the fail-closed boundary lives
 * elsewhere.
 */
@Mixin(ServerCommonPacketListenerImpl.class)
public abstract class ServerCommonPacketListenerImplMixin {

        /**
         * Debug-only logger for unexpected internal states (never the security log).
         */
        @Unique
        private static final Logger SECUREAUTH_LOG = LoggerFactory.getLogger("secureauth.mixin");

        @Inject(method = "send(Lnet/minecraft/network/protocol/Packet;)V", at = @At("HEAD"), cancellable = true)
        private void secureauth$onSend(Packet<?> packet, CallbackInfo ci) {
                if (secureauth$shouldDrop(packet)) {
                        // void method: plain cancellation drops the packet entirely.
                        ci.cancel();
                }
        }

        @Inject(method = "send(Lnet/minecraft/network/protocol/Packet;Lio/netty/channel/ChannelFutureListener;)V",
                        at = @At("HEAD"), cancellable = true)
        private void secureauth$onSendWithListener(Packet<?> packet, ChannelFutureListener futureListener, CallbackInfo ci) {
                if (secureauth$shouldDrop(packet)) {
                        // void method: plain cancellation drops the packet entirely.
                        ci.cancel();
                }
        }

        /**
         * Drop decision for one outgoing packet.
         * Never throws; every unexpected internal state passes through (see the class javadoc for the
         * reasoning).
         */
        private boolean secureauth$shouldDrop(Packet<?> packet) {
                try {
                        if (packet == null) {
                                return false;
                        }
                        if (PacketBypass.isBypassed()) {
                                return false;
                        }
                        SecureAuth self = SecureAuth.get();
                        if (self == null || !self.enabled()) {
                                return false;
                        }
                        AuthManager manager = self.authManager();
                        if (manager == null) {
                                return false;
                        }
                        if (!((Object) this instanceof ServerGamePacketListenerImpl)) {
                                return false;
                        }
                        return manager.packetFilter().shouldDrop((ServerCommonPacketListenerImpl) (Object) this, packet);
                } catch (Throwable t) {
                        SECUREAUTH_LOG.debug("SecureAuth outgoing packet filter error; packet passes", t);
                        return false;
                }
        }
}
