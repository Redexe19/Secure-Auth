package net.secureauth.ui;

import net.minecraft.ChatFormatting;
import net.minecraft.core.component.DataComponents;
import net.minecraft.network.chat.Component;
import net.minecraft.server.level.ServerPlayer;
import net.minecraft.world.entity.player.Inventory;
import net.minecraft.world.entity.player.Player;
import net.minecraft.world.MenuProvider;
import net.minecraft.world.inventory.MenuType;
import net.minecraft.world.item.ItemStack;
import net.minecraft.world.item.Items;
import net.minecraft.world.item.component.ResolvableProfile;
import net.secureauth.auth.AuthManager;
import net.secureauth.auth.AuthSession;
import net.secureauth.auth.AuthState;
import net.secureauth.lang.Lang;
import net.secureauth.security.SecurityEvent;

/**
 * The player-facing authentication panel: a 27-slot chest menu that works on
 * completely vanilla clients.
 *
 * <p>It replaces the former modded-client auth screen. The panel is the
 * "status + guidance" surface — the actual password is typed in chat with
 * {@code /login} or {@code /register} (a chest grid cannot capture a secret).
 * Clicking the action items sends the matching command hint to chat, and the
 * panel refreshes itself whenever the session state changes (attempts left,
 * lockout countdown, deadline) while it stays open.</p>
 *
 * <p>Layout (3 rows):</p>
 * <pre>
 *   [ filler x4 ] [ player head: account status ] [ filler x4 ]
 *   [ filler x2 ] [ book: log in ] [ barrier: locked ] [ writable book: register ] [ filler x3 ]
 *   [ filler x4 ] [ clock: time left ] [ filler x3 ]
 * </pre>
 */
public final class AuthPanel extends ChestGui {

        // 27-slot layout constants.
        private static final int SLOT_HEAD = 4;
        private static final int SLOT_LOGIN = 11;
        private static final int SLOT_LOCKED = 13;
        private static final int SLOT_REGISTER = 15;
        private static final int SLOT_DEADLINE = 22;

        private final AuthManager manager;
        private final AuthSession session;

        private AuthPanel(int containerId, Inventory playerInventory, AuthManager manager, AuthSession session) {
                super(MenuType.GENERIC_9x3, containerId, playerInventory, 3, session.player);
                this.manager = manager;
                this.session = session;
        }

        /** Opens the panel for the session's player. */
        public static void open(AuthManager manager, AuthSession session) {
                ServerPlayer player = session.player;
                session.openPanel = null;
                player.openMenu(new MenuProvider() {
                        @Override
                        public Component getDisplayName() {
                                // Literal, server-resolved: vanilla clients would show the raw
                                // key for a translatable title.
                                return Lang.plain(player, "auth.panel.title");
                        }

                        @Override
                        public net.minecraft.world.inventory.AbstractContainerMenu createMenu(
                                        int containerId, Inventory inventory, Player viewer) {
                                AuthPanel panel = new AuthPanel(containerId, inventory, manager, session);
                                panel.build();
                                session.openPanel = panel;
                                manager.logger().log(SecurityEvent.PANEL_OPENED, session.usernameNorm, session.ip);
                                return panel;
                        }
                });
        }

        /** Refreshes the panel if this player still has it open. */
        public static void refresh(AuthSession session) {
                AuthPanel panel = session.openPanel;
                if (panel != null) {
                        panel.refresh();
                }
        }

        /** Closes the panel if open (called when authentication succeeds). */
        public static void close(AuthSession session) {
                if (session.openPanel != null && session.player.containerMenu == session.openPanel) {
                        session.player.closeContainer();
                }
                session.openPanel = null;
        }

        @Override
        protected void build() {
                int maxAttempts = manager.config().security.maxLoginAttempts;
                boolean unregistered = session.account == null;
                boolean locked = session.state == AuthState.LOCKED;

                // --- Head: the account status card ------------------------------------
                Component stateName;
                if (session.authenticated()) {
                        stateName = Lang.plain(session.player, "auth.panel.status.authenticated");
                } else if (locked && session.account != null && session.account.locked()) {
                        stateName = Lang.plain(session.player, "auth.panel.status.lockedPermanent");
                } else if (locked) {
                        stateName = Lang.plain(session.player, "auth.panel.status.locked");
                } else if (unregistered) {
                        stateName = Lang.plain(session.player, "auth.panel.status.unregistered");
                } else {
                        stateName = Lang.plain(session.player, "auth.panel.status.awaiting");
                }
                ItemStack head = named(Items.PLAYER_HEAD, Lang.plain(session.player, "auth.panel.head.name"),
                                lore(
                                                Lang.plain(session.player, "auth.panel.head.player")
                                                                .append(Component.literal(session.usernameDisplay)
                                                                                .withStyle(ChatFormatting.WHITE)),
                                                Lang.plain(session.player, "auth.panel.head.state").append(stateName),
                                                line("auth.panel.head.attempts",
                                                                Math.max(0, maxAttempts
                                                                                - (session.account == null ? 0
                                                                                                : session.account.failedAttempts())))));
                head.set(DataComponents.PROFILE, ResolvableProfile.createResolved(session.player.getGameProfile()));
                set(SLOT_HEAD, head);

                // --- Login / register action items -------------------------------------
                if (session.authenticated()) {
                        ItemStack done = named(Items.NETHER_STAR,
                                        Lang.plain(session.player, "auth.panel.done.name").withStyle(ChatFormatting.GREEN),
                                        lore(Lang.plain(session.player, "auth.panel.done.lore")));
                        set(SLOT_LOGIN, done);
                        set(SLOT_REGISTER, fillerPane());
                } else if (locked) {
                        long seconds = session.account != null && !session.account.locked()
                                        ? Math.max(0L, (session.account.lockoutUntil() - System.currentTimeMillis()
                                                        + 999L) / 1000L)
                                        : 0L;
                        ItemStack barrier = named(Items.BARRIER,
                                        Lang.plain(session.player, "auth.panel.locked.name").withStyle(ChatFormatting.RED),
                                        lore(session.account != null && session.account.locked()
                                                        ? line("auth.panel.locked.permanent")
                                                        : line("auth.panel.locked.remaining", seconds)));
                        set(SLOT_LOCKED, barrier);
                        set(SLOT_LOGIN, fillerPane());
                        set(SLOT_REGISTER, fillerPane());
                } else {
                        set(SLOT_LOCKED, fillerPane());
                        if (unregistered) {
                                set(SLOT_LOGIN, fillerPane());
                                ItemStack register = named(Items.WRITABLE_BOOK,
                                                Lang.plain(session.player, "auth.panel.register.name")
                                                                .withStyle(ChatFormatting.GREEN),
                                                lore(line("auth.panel.register.lore1"), line("auth.panel.register.lore2")));
                                register.set(DataComponents.ENCHANTMENT_GLINT_OVERRIDE, true);
                                set(SLOT_REGISTER, register);
                        } else {
                                ItemStack login = named(Items.BOOK,
                                                Lang.plain(session.player, "auth.panel.login.name").withStyle(ChatFormatting.GREEN),
                                                lore(line("auth.panel.login.lore1"), line("auth.panel.login.lore2")));
                                login.set(DataComponents.ENCHANTMENT_GLINT_OVERRIDE, true);
                                set(SLOT_LOGIN, login);
                                set(SLOT_REGISTER, fillerPane());
                        }
                }

                // --- Deadline clock -------------------------------------------------------
                if (!session.authenticated()) {
                        ItemStack clock = named(Items.CLOCK,
                                        Lang.plain(session.player, "auth.panel.deadline.name").withStyle(ChatFormatting.GOLD),
                                        lore(line("auth.panel.deadline.lore", session.secondsUntilDeadline())));
                        set(SLOT_DEADLINE, clock);
                } else {
                        set(SLOT_DEADLINE, fillerPane());
                }

                fill();
        }

        @Override
        protected void onClick(int slot) {
                if (slot == SLOT_LOGIN && !session.authenticated() && !sessionStateLocked()) {
                        manager.sendTranslated(viewer(), "auth.panel.login.hint");
                } else if (slot == SLOT_REGISTER && session.account == null && !sessionStateLocked()) {
                        manager.sendTranslated(viewer(), "auth.panel.register.hint");
                }
                // All other slots are informational.
        }

        private boolean sessionStateLocked() {
                return session.state == AuthState.LOCKED;
        }

        @Override
        protected void onClickSpam() {
                manager.logger().log(SecurityEvent.INVALID_AUTH_PACKET, session.usernameNorm, session.ip,
                                "panel_click_spam");
        }

        @Override
        protected void onClosed() {
                if (session.openPanel == this) {
                        session.openPanel = null;
                }
        }

        @Override
        public Component title() {
                return Lang.plain(viewer(), "auth.panel.title");
        }
}
