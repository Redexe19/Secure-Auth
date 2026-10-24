package net.secureauth.mixin;

import net.minecraft.world.entity.Entity;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.gen.Invoker;

/**
 * Exposes unsetRemoved() (protected in vanilla) to the mod.
 * That is the exact mechanism behind the "extremely laggy server fails to send the player out of the
 * auth dimension" report: clearing the flag (exactly what vanilla itself does mid-transfer via
 * unsetRemoved()) makes the rescue teleport work.
 */
@Mixin(Entity.class)
public interface EntityMixin {

        /**
         * Invokes the protected unsetRemoved() on the target entity.
         */
        @Invoker("unsetRemoved")
        void secureauth$unsetRemoved();
}
