package net.secureauth.mixin;

import net.minecraft.network.PacketSendListener;
import net.minecraft.network.protocol.Packet;
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

@Mixin(ServerGamePacketListenerImpl.class)
public abstract class ServerGamePacketListenerImplMixin {
    @Unique private static final Logger SECUREAUTH_LOG = LoggerFactory.getLogger("secureauth.mixin");

    @Inject(method = "send(Lnet/minecraft/network/protocol/Packet;)V", at = @At("HEAD"), cancellable = true)
    private void secureauth$onSend(Packet<?> packet, CallbackInfo ci) {
        if (secureauth$shouldDrop(packet)) ci.cancel();
    }

    @Inject(method = "send(Lnet/minecraft/network/protocol/Packet;Lnet/minecraft/network/PacketSendListener;)V", at = @At("HEAD"), cancellable = true)
    private void secureauth$onSendWithListener(Packet<?> packet, PacketSendListener callback, CallbackInfo ci) {
        if (secureauth$shouldDrop(packet)) ci.cancel();
    }

    @Unique private boolean secureauth$shouldDrop(Packet<?> packet) {
        try {
            if (packet == null || PacketBypass.isBypassed()) return false;
            SecureAuth self = SecureAuth.get();
            if (self == null || !self.enabled()) return false;
            AuthManager manager = self.authManager();
            return manager != null && manager.packetFilter().shouldDrop((ServerGamePacketListenerImpl)(Object)this, packet);
        } catch (Throwable t) {
            SECUREAUTH_LOG.debug("SecureAuth outgoing packet filter error; packet passes", t);
            return false;
        }
    }
}
