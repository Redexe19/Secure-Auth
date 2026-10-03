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
 *
 * <p><b>What it blocks.</b> Both {@code send} overloads of the common packet
 * listener are intercepted at HEAD; when
 * {@link net.secureauth.network.PacketFilterService#shouldDrop} decides the
 * packet would leak real-world information to a specific unauthenticated
 * viewer (other players' tab-list entries, chat broadcasts,
 * maps, optionally scoreboards and custom payloads), the send is cancelled and
 * the packet never reaches the connection. SecureAuth's own packets (auth
 * prompts, the tab-list hiding packets, ...) are exempt via
 * {@link PacketBypass#isBypassed()}.</p>
 *
 * <p><b>Verified targets</b> (minijavap + {@code javap -c} on the 26.2
 * game-server jar): both methods are public, return {@code void} and have the
 * exact descriptors {@code send(Lnet/minecraft/network/protocol/Packet;)V} and
 * {@code send(Lnet/minecraft/network/protocol/Packet;Lio/netty/channel/ChannelFutureListener;)V}.
 * The one-argument overload delegates to the two-argument one with a
 * {@code null} listener, so a packet that passes here is checked exactly once
 * more in the delegate — {@code shouldDrop} is a pure, idempotent lookup, so
 * the double check is harmless and keeps both entry points covered even if the
 * delegation changes in a future version. Because both targets return
 * {@code void}, cancellation uses {@code ci.cancel()} (plain
 * {@code CallbackInfo}; there is no {@code setReturnValue} on it).</p>
 *
 * <p><b>Fail-open by design — and why that is safe here.</b> This filter is
 * information isolation, not the security boundary: it only hides cosmetic
 * world data. {@code shouldDrop} itself returns "pass" when the viewer has no
 * session or is authenticated, and this mixin deliberately mirrors that
 * behaviour instead of pre-checking the session: a missing session means the
 * mod never quarantined this player (the player joined while the mod was
 * inert/disabled, or the listener is not a game-phase listener at all), so
 * there is no quarantine whose information boundaries could be violated. The
 * actual fail-closed boundary — no movement, no actions, no commands, no item
 * pickup without authentication — is enforced by the other three mixins and by
 * {@code AuthManager.tick}/{@code AuthWorldManager.tick}. Nothing is logged
 * from this hot path (it runs for every outgoing packet) to avoid spam.</p>
 *
 * <p><b>Guard order</b> (all null-safe, no exceptions ever escape):</p>
 * <ol>
 *   <li>{@link PacketBypass#isBypassed()} — SecureAuth's own sends pass.</li>
 *   <li>{@link SecureAuth#get()} {@code null} or {@code enabled() == false} — inert mod.</li>
 *   <li>{@code authManager() == null} — disabled/shutting-down mod.</li>
 *   <li>{@code (Object)this instanceof ServerGamePacketListenerImpl} — only the
 *       play phase carries world information; configuration/login listeners pass.</li>
 *   <li>{@link net.secureauth.network.PacketFilterService#shouldDrop} decides
 *       (it re-checks bypass, listener type, {@code player}, session state and
 *       the config switches).</li>
 * </ol>
 *
 * <p>Unexpected internal errors are caught, logged at debug level and treated
 * as "pass": an error in the isolation layer must never break packet delivery
 * for everyone; the fail-closed boundary lives elsewhere.</p>
 */
@Mixin(ServerCommonPacketListenerImpl.class)
public abstract class ServerCommonPacketListenerImplMixin {

        /** Debug-only logger for unexpected internal states (never the security log). */
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
         * Drop decision for one outgoing packet. Never throws; every unexpected
         * internal state passes through (see the class javadoc for the reasoning).
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
