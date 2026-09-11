package net.secureauth.ui;

import net.minecraft.ChatFormatting;
import net.minecraft.core.component.DataComponents;
import net.minecraft.network.chat.Component;
import net.minecraft.server.level.ServerPlayer;
import net.minecraft.world.SimpleContainer;
import net.minecraft.world.entity.player.Inventory;
import net.minecraft.world.entity.player.Player;
import net.minecraft.world.inventory.ChestMenu;
import net.minecraft.world.inventory.ContainerInput;
import net.minecraft.world.inventory.MenuType;
import net.minecraft.world.item.Item;
import net.minecraft.world.item.ItemStack;
import net.minecraft.world.item.Items;
import net.minecraft.world.item.component.ItemLore;
import net.secureauth.lang.Lang;

import java.util.ArrayList;
import java.util.List;

/**
 * Base class for SecureAuth's server-built chest menus — the "economy shop
 * plugin" GUI pattern for vanilla clients.
 *
 * <p>The server opens a menu whose {@link MenuType} is one of the vanilla
 * generic 9xN chest types, so an unmodified client renders it as an ordinary
 * chest screen. Clicks arrive as ordinary container-click packets; this class
 * intercepts them (never calling {@code super.clicked}) so the virtual button
 * items can never be picked up, moved or duplicated. The vanilla click
 * protocol self-corrects the client's optimistic prediction, so a swallowed
 * click simply snaps back on the player's screen.</p>
 *
 * <p>Every item name and lore line is resolved server-side into literal text
 * (vanilla clients have no {@code auth.*} translations — translatable
 * components would render as raw keys inside the chest screen).</p>
 *
 * <p>Every subclass is viewer-bound ({@link #stillValid} fails for anyone
 * else) and rate-limited against click spam.</p>
 */
public abstract class ChestGui extends ChestMenu {

        /** Minimum gap between two processed clicks on the same panel. */
        private static final long CLICK_MIN_INTERVAL_MS = 100L;

        /** Minimum gap between two click-spam log entries. */
        private static final long SPAM_LOG_INTERVAL_MS = 5_000L;

        private final ServerPlayer viewer;

        private long lastClickAt;
        private long lastSpamLogAt;

        protected ChestGui(MenuType<?> type, int containerId, Inventory playerInventory, int rows,
                        ServerPlayer viewer) {
                super(type, containerId, playerInventory, new SimpleContainer(rows * 9), rows);
                this.viewer = viewer;
        }

        /** The player this menu was built for. */
        protected final ServerPlayer viewer() {
                return viewer;
        }

        /** The virtual container backing the chest grid. */
        protected final SimpleContainer gui() {
                return (SimpleContainer) getContainer();
        }

        // ------------------------------------------------------------------
        // Item helpers
        // ------------------------------------------------------------------

        /** Places a button item into a chest-grid slot. */
        protected final void set(int slot, ItemStack stack) {
                gui().setItem(slot, stack);
        }

        /** Fills every grid slot that is currently air with the filler pane. */
        protected final void fill() {
                int size = getRowCount() * 9;
                for (int slot = 0; slot < size; slot++) {
                        if (gui().getItem(slot).isEmpty()) {
                                set(slot, fillerPane());
                        }
                }
        }

        /** An item with a custom (non-italic) display name. */
        protected static ItemStack named(Item item, Component name) {
                ItemStack stack = new ItemStack(item);
                stack.set(DataComponents.ITEM_NAME, name);
                return stack;
        }

        /** An item with a custom name plus a lore list (dark gray by convention). */
        protected static ItemStack named(Item item, Component name, List<Component> lore) {
                ItemStack stack = named(item, name);
                stack.set(DataComponents.LORE, new ItemLore(lore));
                return stack;
        }

        /** Convenience lore builder. */
        protected static List<Component> lore(Component... lines) {
                List<Component> list = new ArrayList<>(lines.length);
                for (Component line : lines) {
                        list.add(line);
                }
                return list;
        }

        /** A single gray lore line, resolved server-side for the viewer's language. */
        protected final Component line(String key) {
                return Lang.plain(viewer(), key).withStyle(ChatFormatting.GRAY);
        }

        /** A single gray lore line with one argument, resolved server-side. */
        protected final Component line(String key, Object arg) {
                return Lang.plain(viewer(), key, arg).withStyle(ChatFormatting.GRAY);
        }

        // ------------------------------------------------------------------
        // Click interception
        // ------------------------------------------------------------------

        @Override
        public final void clicked(int slotIndex, int button, ContainerInput clickType, Player player) {
                if (player != viewer) {
                        return;
                }
                long now = System.currentTimeMillis();
                if (now - lastClickAt < CLICK_MIN_INTERVAL_MS) {
                        // Rapid multi-click: ignore, and log a single INVALID_AUTH_PACKET per window.
                        if (now - lastSpamLogAt > SPAM_LOG_INTERVAL_MS) {
                                lastSpamLogAt = now;
                                onClickSpam();
                        }
                        return;
                }
                lastClickAt = now;

                int gridSize = getRowCount() * 9;
                if (slotIndex >= 0 && slotIndex < gridSize) {
                        onClick(slotIndex);
                }
                // Deliberately never super.clicked(): the virtual items are buttons,
                // and the client's optimistic prediction is corrected by the vanilla
                // sync protocol that runs right after this method returns.
        }

        /** A real (rate-limited) click on chest-grid slot {@code slot}. */
        protected abstract void onClick(int slot);

        /** Called at most once per spam window when clicks arrive faster than allowed. */
        protected void onClickSpam() {
                // Subclasses override to audit-log the abuse.
        }

        @Override
        public final ItemStack quickMoveStack(Player player, int index) {
                // Shift-clicks are swallowed like every other interaction.
                return ItemStack.EMPTY;
        }

        @Override
        public boolean stillValid(Player player) {
                return player == viewer && !viewer.isRemoved();
        }

        @Override
        public void removed(Player player) {
                super.removed(player);
                if (player == viewer) {
                        onClosed();
                }
        }

        /** Called when the viewer closes the menu (or is disconnected). */
        protected void onClosed() {
                // Subclasses override to clear session state.
        }

        /** Pushes any item changes made since the last sync to the client. */
        public final void sync() {
                broadcastChanges();
        }

        /** Rebuilds every grid item (after a state change) and syncs the client. */
        public final void refresh() {
                int size = getRowCount() * 9;
                for (int slot = 0; slot < size; slot++) {
                        gui().setItem(slot, ItemStack.EMPTY);
                }
                build();
                sync();
        }

        /** (Re)builds the grid contents. Called on open and on every {@link #refresh()}. */
        protected abstract void build();

        /** Menu title shown above the chest grid. */
        public abstract Component title();

        // ------------------------------------------------------------------
        // Shared button items
        // ------------------------------------------------------------------

        /** The gray filler pane used for empty grid slots (name is a single space). */
        protected static ItemStack fillerPane() {
                return named(Items.STAINED_GLASS_PANE.gray(), Component.literal(" "));
        }
}
