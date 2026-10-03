package net.secureauth.ui;

import net.minecraft.component.DataComponentTypes;
import net.minecraft.component.type.LoreComponent;
import net.minecraft.entity.player.PlayerEntity;
import net.minecraft.entity.player.PlayerInventory;
import net.minecraft.inventory.SimpleInventory;
import net.minecraft.item.Item;
import net.minecraft.item.ItemStack;
import net.minecraft.item.Items;
import net.minecraft.screen.GenericContainerScreenHandler;
import net.minecraft.screen.ScreenHandlerType;
import net.minecraft.screen.slot.SlotActionType;
import net.minecraft.server.network.ServerPlayerEntity;
import net.minecraft.text.Text;
import net.minecraft.util.Formatting;
import net.secureauth.lang.Lang;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Base class for SecureAuth's server-built chest menus — the "economy shop
 * plugin" GUI pattern for vanilla clients.
 *
 * <p>The server opens a menu whose {@link ScreenHandlerType} is one of the vanilla
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
 * <p>Every subclass is viewer-bound ({@link #canUse} fails for anyone
 * else) and rate-limited against click spam.</p>
 */
public abstract class ChestGui extends GenericContainerScreenHandler {

        /** Minimum gap between two processed clicks on the same panel. */
        private static final long CLICK_MIN_INTERVAL_NANOS = TimeUnit.MILLISECONDS.toNanos(100L);

        /** Minimum gap between two click-spam log entries. */
        private static final long SPAM_LOG_INTERVAL_NANOS = TimeUnit.SECONDS.toNanos(5L);

        private final ServerPlayerEntity viewer;

        private long lastClickAtNanos;
        private long lastSpamLogAtNanos;

        protected ChestGui(ScreenHandlerType<?> type, int containerId, PlayerInventory playerInventory, int rows,
                        ServerPlayerEntity viewer) {
                super(type, containerId, playerInventory, new SimpleInventory(rows * 9), rows);
                this.viewer = viewer;
        }

        /** The player this menu was built for. */
        protected final ServerPlayerEntity viewer() {
                return viewer;
        }

        /** The virtual container backing the chest grid. */
        protected final SimpleInventory gui() {
                return (SimpleInventory) getInventory();
        }

        // ------------------------------------------------------------------
        // Item helpers
        // ------------------------------------------------------------------

        /** Places a button item into a chest-grid slot. */
        protected final void set(int slot, ItemStack stack) {
                gui().setStack(slot, stack);
        }

        /** Fills every grid slot that is currently air with the filler pane. */
        protected final void fill() {
                int size = getRows() * 9;
                for (int slot = 0; slot < size; slot++) {
                        if (gui().getStack(slot).isEmpty()) {
                                set(slot, fillerPane());
                        }
                }
        }

        /** An item with a custom (non-italic) display name. */
        protected static ItemStack named(Item item, Text name) {
                ItemStack stack = new ItemStack(item);
                stack.set(DataComponentTypes.ITEM_NAME, name);
                return stack;
        }

        /** An item with a custom name plus a lore list (dark gray by convention). */
        protected static ItemStack named(Item item, Text name, List<Text> lore) {
                ItemStack stack = named(item, name);
                stack.set(DataComponentTypes.LORE, new LoreComponent(lore));
                return stack;
        }

        /** Convenience lore builder. */
        protected static List<Text> lore(Text... lines) {
                List<Text> list = new ArrayList<>(lines.length);
                for (Text line : lines) {
                        list.add(line);
                }
                return list;
        }

        /** A single gray lore line, resolved server-side for the viewer's language. */
        protected final Text line(String key) {
                return Lang.plain(viewer(), key).formatted(Formatting.GRAY);
        }

        /** A single gray lore line with one argument, resolved server-side. */
        protected final Text line(String key, Object arg) {
                return Lang.plain(viewer(), key, arg).formatted(Formatting.GRAY);
        }

        // ------------------------------------------------------------------
        // Click interception
        // ------------------------------------------------------------------

        @Override
        public final void onSlotClick(int slotIndex, int button, SlotActionType clickType, PlayerEntity player) {
                if (player != viewer) {
                        return;
                }
                long now = System.nanoTime();
                if (lastClickAtNanos != 0L && now - lastClickAtNanos < CLICK_MIN_INTERVAL_NANOS) {
                        // Rapid multi-click: ignore, and log a single INVALID_AUTH_PACKET per window.
                        if (lastSpamLogAtNanos == 0L || now - lastSpamLogAtNanos >= SPAM_LOG_INTERVAL_NANOS) {
                                lastSpamLogAtNanos = now;
                                onClickSpam();
                        }
                        return;
                }
                lastClickAtNanos = now;

                int gridSize = getRows() * 9;
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
        public final ItemStack quickMove(PlayerEntity player, int index) {
                // Shift-clicks are swallowed like every other interaction.
                return ItemStack.EMPTY;
        }

        @Override
        public boolean canUse(PlayerEntity player) {
                return player == viewer && !viewer.isRemoved();
        }

        @Override
        public void onClosed(PlayerEntity player) {
                super.onClosed(player);
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
                sendContentUpdates();
        }

        /** Rebuilds every grid item (after a state change) and syncs the client. */
        public final void refresh() {
                int size = getRows() * 9;
                for (int slot = 0; slot < size; slot++) {
                        gui().setStack(slot, ItemStack.EMPTY);
                }
                build();
                sync();
        }

        /** (Re)builds the grid contents. Called on open and on every {@link #refresh()}. */
        protected abstract void build();

        /** Menu title shown above the chest grid. */
        public abstract Text title();

        // ------------------------------------------------------------------
        // Shared button items
        // ------------------------------------------------------------------

        /** The gray filler pane used for empty grid slots (name is a single space). */
        protected static ItemStack fillerPane() {
                return named(Items.GRAY_STAINED_GLASS_PANE, Text.literal(" "));
        }
}
