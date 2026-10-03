package net.secureauth.mixin;

import net.minecraft.world.entity.Entity;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.gen.Invoker;

/**
 * Exposes {@link Entity#unsetRemoved()} (protected in vanilla) to the mod.
 *
 * <p>Since 1.2.4 the world manager uses it before re-teleporting a player who
 * is stuck inside the auth dimension: a half-finished dimension transfer can
 * leave the player entity flagged {@code removed} while the connection still
 * points at it — and {@code ServerPlayer.teleport()} hard-returns for removed
 * entities, so every subsequent teleport silently no-ops. That is the exact
 * mechanism behind the "extremely laggy server fails to send the player out of
 * the auth dimension" report: clearing the flag (exactly what vanilla itself
 * does mid-transfer via {@code unsetRemoved()}) makes the rescue teleport work.</p>
 */
@Mixin(Entity.class)
public interface EntityMixin {

        /** Invokes the protected {@link Entity#unsetRemoved()} on the target entity. */
        @Invoker("unsetRemoved")
        void secureauth$unsetRemoved();
}
