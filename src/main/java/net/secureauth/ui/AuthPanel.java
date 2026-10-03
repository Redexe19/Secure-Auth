package net.secureauth.ui;

import net.minecraft.component.DataComponentTypes;
import net.minecraft.component.type.ProfileComponent;
import net.minecraft.entity.player.PlayerEntity;
import net.minecraft.entity.player.PlayerInventory;
import net.minecraft.item.ItemStack;
import net.minecraft.item.Items;
import net.minecraft.screen.NamedScreenHandlerFactory;
import net.minecraft.screen.ScreenHandlerType;
import net.minecraft.server.network.ServerPlayerEntity;
import net.minecraft.text.Text;
import net.minecraft.util.Formatting;
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
        private static final int SLOT_PASSWORD_SAFETY = 26;

        private final AuthManager manager;
        private final AuthSession session;

        private AuthPanel(int containerId, PlayerInventory playerInventory, AuthManager manager, AuthSession session) {
                super(ScreenHandlerType.GENERIC_9X3, containerId, playerInventory, 3, session.player);
                this.manager = manager;
                this.session = session;
        }

        /** Opens the panel for the session's player. */
        public static void open(AuthManager manager, AuthSession session) {
                ServerPlayerEntity player = session.player;
                session.openPanel = null;
                player.openHandledScreen(new NamedScreenHandlerFactory() {
                        @Override
                        public Text getDisplayName() {
                                // Literal, server-resolved: vanilla clients would show the raw
                                // key for a translatable title.
                                return Lang.plain(player, "auth.panel.title");
                        }

                        @Override
                        public net.minecraft.screen.ScreenHandler createMenu(
                                        int containerId, PlayerInventory inventory, PlayerEntity viewer) {
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
                if (session.openPanel != null && session.player.currentScreenHandler == session.openPanel) {
                        session.player.closeHandledScreen();
                }
                session.openPanel = null;
        }

        @Override
        protected void build() {
                int maxAttempts = manager.config().security.maxLoginAttempts;
                boolean unregistered = session.account == null;
                boolean locked = session.state == AuthState.LOCKED;

                // --- Head: the account status card ------------------------------------
                Text stateName;
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
                                                                .append(Text.literal(session.usernameDisplay)
                                                                                .formatted(Formatting.WHITE)),
                                                Lang.plain(session.player, "auth.panel.head.state").append(stateName),
                                                line("auth.panel.head.attempts",
                                                                Math.max(0, maxAttempts
                                                                                - (session.account == null ? 0
                                                                                                : session.account.failedAttempts())))));
                head.set(DataComponentTypes.PROFILE, new ProfileComponent(session.player.getGameProfile()));
                set(SLOT_HEAD, head);

                // --- Login / register action items -------------------------------------
                if (session.authenticated()) {
                        ItemStack done = named(Items.NETHER_STAR,
                                        Lang.plain(session.player, "auth.panel.done.name").formatted(Formatting.GREEN),
                                        lore(Lang.plain(session.player, "auth.panel.done.lore")));
                        set(SLOT_LOGIN, done);
                        set(SLOT_REGISTER, fillerPane());
                } else if (locked) {
                        long seconds = session.account != null && !session.account.locked()
                                        ? Math.max(0L, (session.account.lockoutUntil() - System.currentTimeMillis()
                                                        + 999L) / 1000L)
                                        : 0L;
                        ItemStack barrier = named(Items.BARRIER,
                                        Lang.plain(session.player, "auth.panel.locked.name").formatted(Formatting.RED),
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
                                                                .formatted(Formatting.GREEN),
                                                lore(line("auth.panel.register.lore1"), line("auth.panel.register.lore2")));
                                register.set(DataComponentTypes.ENCHANTMENT_GLINT_OVERRIDE, true);
                                set(SLOT_REGISTER, register);
                        } else {
                                ItemStack login = named(Items.BOOK,
                                                Lang.plain(session.player, "auth.panel.login.name").formatted(Formatting.GREEN),
                                                lore(line("auth.panel.login.lore1"), line("auth.panel.login.lore2")));
                                login.set(DataComponentTypes.ENCHANTMENT_GLINT_OVERRIDE, true);
                                set(SLOT_LOGIN, login);
                                set(SLOT_REGISTER, fillerPane());
                        }
                }

                // --- Deadline clock -------------------------------------------------------
                if (!session.authenticated()) {
                        ItemStack clock = named(Items.CLOCK,
                                        Lang.plain(session.player, "auth.panel.deadline.name").formatted(Formatting.GOLD),
                                        lore(line("auth.panel.deadline.lore", session.secondsUntilDeadline())));
                        set(SLOT_DEADLINE, clock);
                } else {
                        set(SLOT_DEADLINE, fillerPane());
                }

                set(SLOT_PASSWORD_SAFETY, named(Items.PAPER,
                                Lang.plain(session.player, "auth.panel.passwordSafety.name")
                                                .formatted(Formatting.YELLOW),
                                lore(line("auth.panel.passwordSafety.lore1"),
                                                line("auth.panel.passwordSafety.lore2"))));

                fill();
        }

        @Override
        protected void onClick(int slot) {
                if (slot == SLOT_LOGIN && !session.authenticated() && !sessionStateLocked()) {
                        manager.sendTranslated(viewer(), "auth.panel.login.hint");
                } else if (slot == SLOT_REGISTER && session.account == null && !sessionStateLocked()) {
                        manager.sendTranslated(viewer(), "auth.panel.register.hint");
                } else if (slot == SLOT_PASSWORD_SAFETY) {
                        manager.sendTranslated(viewer(), "auth.panel.passwordSafety.hint");
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
        public Text title() {
                return Lang.plain(viewer(), "auth.panel.title");
        }
}
