package net.secureauth.ui;

import java.util.List;
import net.minecraft.component.DataComponentTypes;
import net.minecraft.component.type.ProfileComponent;
import net.minecraft.entity.player.PlayerEntity;
import net.minecraft.entity.player.PlayerInventory;
import net.minecraft.item.ItemStack;
import net.minecraft.item.Items;
import net.minecraft.screen.NamedScreenHandlerFactory;
import net.minecraft.screen.ScreenHandler;
import net.minecraft.screen.ScreenHandlerType;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.network.ServerPlayerEntity;
import net.minecraft.text.Text;
import net.minecraft.util.Formatting;
import net.secureauth.account.Account;
import net.secureauth.account.StoreException;
import net.secureauth.auth.AuthManager;
import net.secureauth.auth.AuthSession;
import net.secureauth.auth.AuthState;
import net.secureauth.lang.Lang;
import net.secureauth.security.SecurityEvent;

/**
 * The administrator's chest panel — an economy-shop-style GUI over the live
 * session table, opened with {@code /auth panel} (admin permission).
 *
 * <p>The first page lists every online player as a head whose lore carries the
 * live authentication state. Clicking a head opens the detail page with the
 * same actions the {@code /auth lock|unlock|forcelogout} subcommands offer,
 * plus the password-reset hint (a secret can never be typed into a chest
 * grid, so the reset action prints the command into chat instead). Every
 * action routes through {@link AuthManager} and lands in the security log
 * exactly like its command twin.</p>
 */
public final class AdminPanel extends ChestGui {

        /** Online players shown per page (rows 1-5 of the 6-row grid). */
        private static final int PLAYERS_PER_PAGE = 45;

        private static final int SLOT_SUMMARY = 4;
        private static final int SLOT_PREV = 45;
        private static final int SLOT_PAGE = 49;
        private static final int SLOT_NEXT = 53;

        private final AuthManager manager;
        private final MinecraftServer server;
        private final int page;

        private AdminPanel(int containerId, PlayerInventory playerInventory, AuthManager manager,
                        MinecraftServer server, int page) {
                super(ScreenHandlerType.GENERIC_9X6, containerId, playerInventory, 6, (ServerPlayerEntity) playerInventory.player);
                this.manager = manager;
                this.server = server;
                this.page = page;
        }

        /** Opens the admin panel (page 0) for an administrator. */
        public static void open(AuthManager manager, ServerPlayerEntity admin) {
                openPage(manager, admin, 0);
        }

        private static void openPage(AuthManager manager, ServerPlayerEntity admin, int page) {
                MinecraftServer server = admin.getEntityWorld().getServer();
                admin.openHandledScreen(new NamedScreenHandlerFactory() {
                        @Override
                        public Text getDisplayName() {
                                // Literal, server-resolved title (vanilla clients have no auth.* translations).
                                return Lang.plain(admin, "auth.admin.panel.title");
                        }

                        @Override
                        public ScreenHandler createMenu(int containerId, PlayerInventory inventory, PlayerEntity viewer) {
                                AdminPanel panel = new AdminPanel(containerId, inventory, manager,
                                                server, page);
                                panel.build();
                                manager.logger().log(SecurityEvent.PANEL_OPENED,
                                                admin.getGameProfile().name(), admin.getIp(), "admin");
                                return panel;
                        }
                });
        }

        @Override
        protected void build() {
                List<ServerPlayerEntity> online = List.copyOf(server.getPlayerManager().getPlayerList());
                int totalPages = Math.max(1, (online.size() + PLAYERS_PER_PAGE - 1) / PLAYERS_PER_PAGE);
                int safePage = Math.min(page, totalPages - 1);
                int from = safePage * PLAYERS_PER_PAGE;
                int to = Math.min(online.size(), from + PLAYERS_PER_PAGE);

                // --- Summary item -----------------------------------------------------------
                long authenticated = online.stream()
                                .map(manager::session)
                                .filter(s -> s != null && s.authenticated())
                                .count();
                ItemStack summary = named(Items.NETHER_STAR,
                                Lang.plain(viewer(), "auth.admin.panel.summary.name")
                                                .formatted(Formatting.GOLD),
                                lore(
                                                line("auth.admin.panel.summary.online", online.size()),
                                                line("auth.admin.panel.summary.authenticated", authenticated),
                                                line("auth.admin.panel.summary.unauthenticated", online.size() - authenticated)));
                set(SLOT_SUMMARY, summary);

                // --- Player heads -------------------------------------------------------------
                int gridSlot = 9;
                for (int i = from; i < to; i++) {
                        ServerPlayerEntity target = online.get(i);
                        set(gridSlot++, playerHead(target));
                }

                // --- Pagination row -------------------------------------------------------------
                if (safePage > 0) {
                        set(SLOT_PREV, named(Items.ARROW,
                                        Lang.plain(viewer(), "auth.admin.panel.prev").formatted(Formatting.YELLOW)));
                }
                if (safePage < totalPages - 1) {
                        set(SLOT_NEXT, named(Items.ARROW,
                                        Lang.plain(viewer(), "auth.admin.panel.next").formatted(Formatting.YELLOW)));
                }
                set(SLOT_PAGE, named(Items.PAPER,
                                Lang.plain(viewer(), "auth.admin.panel.page", safePage + 1, totalPages)
                                                .formatted(Formatting.WHITE)));

                fill();
        }

        private ItemStack playerHead(ServerPlayerEntity target) {
                AuthSession session = manager.session(target);
                boolean authed = session != null && session.authenticated();
                boolean locked = session != null && session.state == AuthState.LOCKED;
                int maxAttempts = manager.config().security.maxLoginAttempts;
                int failed = session != null && session.account != null ? session.account.failedAttempts() : 0;

                Text state = authed
                                ? Lang.plain(viewer(), "auth.panel.status.authenticated")
                                : locked ? Lang.plain(viewer(), "auth.panel.status.locked")
                                                : Lang.plain(viewer(), "auth.panel.status.awaiting");
                ItemStack head = named(Items.PLAYER_HEAD,
                                Text.literal(target.getGameProfile().name()).formatted(Formatting.WHITE),
                                lore(
                                                Lang.plain(viewer(), "auth.admin.detail.state").append(state),
                                                line("auth.admin.detail.attempts", Math.max(0, maxAttempts - failed)),
                                                line("auth.admin.detail.ip", session == null ? "?" : session.ip)));
                head.set(DataComponentTypes.PROFILE, ProfileComponent.ofStatic(target.getGameProfile()));
                return head;
        }

        @Override
        protected void onClick(int slot) {
                ServerPlayerEntity admin = viewer();
                if (!isAdmin(admin)) {
                        // The permission may have been revoked (or the admin was logged out)
                        // while the panel was open: re-check on every click.
                        admin.closeHandledScreen();
                        return;
                }
                if (slot == SLOT_PREV && page > 0) {
                        openPage(manager, admin, page - 1);
                        return;
                }
                if (slot == SLOT_NEXT) {
                        openPage(manager, admin, page + 1);
                        return;
                }
                if (slot >= 9 && slot < 9 + PLAYERS_PER_PAGE) {
                        List<ServerPlayerEntity> online = List.copyOf(server.getPlayerManager().getPlayerList());
                        int totalPages = Math.max(1, (online.size() + PLAYERS_PER_PAGE - 1) / PLAYERS_PER_PAGE);
                        int safePage = Math.min(page, totalPages - 1);
                        int index = safePage * PLAYERS_PER_PAGE + (slot - 9);
                        if (index < online.size()) {
                                AdminPlayerDetail.open(manager, admin, online.get(index));
                        }
                }
        }

        @Override
        protected void onClickSpam() {
                manager.logger().log(SecurityEvent.INVALID_AUTH_PACKET, viewer().getGameProfile().name(),
                                viewer().getIp(), "admin_panel_click_spam");
        }

        /** Admin gate re-checked per click: the same check as /auth panel. */
        private boolean isAdmin(ServerPlayerEntity admin) {
                int level = Math.min(4, Math.max(1, manager.config().administration.adminOpLevel));
                try {
                        return admin.hasPermissionLevel(level);
                } catch (RuntimeException e) {
                        return false;
                }
        }

        @Override
        public Text title() {
                return Lang.plain(viewer(), "auth.admin.panel.title");
        }

        // ------------------------------------------------------------------
        // Detail page
        // ------------------------------------------------------------------

        /** The per-player detail page reached by clicking a head. */
        static final class AdminPlayerDetail extends ChestGui {

                private static final int SLOT_HEAD = 4;
                private static final int SLOT_LOCK = 19;
                private static final int SLOT_UNLOCK = 21;
                private static final int SLOT_FORCE_LOGOUT = 23;
                private static final int SLOT_RESET_HINT = 25;
                private static final int SLOT_BACK = 18;

                private final AuthManager manager;
                private final ServerPlayerEntity target;

                private AdminPlayerDetail(int containerId, PlayerInventory playerInventory, AuthManager manager,
                                ServerPlayerEntity target) {
                        super(ScreenHandlerType.GENERIC_9X3, containerId, playerInventory, 3, (ServerPlayerEntity) playerInventory.player);
                        this.manager = manager;
                        this.target = target;
                }

                static void open(AuthManager manager, ServerPlayerEntity admin, ServerPlayerEntity target) {
                        admin.openHandledScreen(new NamedScreenHandlerFactory() {
                                @Override
                                public Text getDisplayName() {
                                        // Literal, server-resolved title (vanilla clients have no auth.* translations).
                                        return Lang.plain(admin, "auth.admin.detail.title",
                                                        target.getGameProfile().name());
                                }

                                @Override
                                public ScreenHandler createMenu(int containerId, PlayerInventory inventory,
                                                PlayerEntity viewer) {
                                        AdminPlayerDetail detail = new AdminPlayerDetail(containerId, inventory,
                                                        manager, target);
                                        detail.build();
                                        return detail;
                                }
                        });
                }

                @Override
                protected void build() {
                        AuthSession session = manager.session(target);
                        Account account = session == null ? null : session.account;
                        boolean authed = session != null && session.authenticated();
                        boolean locked = account != null && account.locked();
                        int maxAttempts = manager.config().security.maxLoginAttempts;

                        Text state = authed
                                        ? Lang.plain(viewer(), "auth.panel.status.authenticated")
                                        : locked ? Lang.plain(viewer(), "auth.panel.status.lockedPermanent")
                                                        : Lang.plain(viewer(), "auth.panel.status.awaiting");

                        ItemStack head = named(Items.PLAYER_HEAD,
                                        Text.literal(target.getGameProfile().name()).formatted(Formatting.WHITE),
                                        lore(
                                                        Lang.plain(viewer(), "auth.admin.detail.state").append(state),
                                                        line("auth.admin.detail.attempts",
                                                                        account == null ? maxAttempts
                                                                                        : Math.max(0, maxAttempts - account.failedAttempts())),
                                                        line("auth.admin.detail.ip", session == null ? "?" : session.ip),
                                                        line("auth.admin.detail.algorithm",
                                                                        account == null ? "-" : account.algorithm())));
                        head.set(DataComponentTypes.PROFILE, ProfileComponent.ofStatic(target.getGameProfile()));
                        set(SLOT_HEAD, head);

                        set(SLOT_LOCK, locked ? fillerPane()
                                        : named(Items.BARRIER, Lang.plain(viewer(), "auth.admin.action.lock.name")
                                                        .formatted(Formatting.RED),
                                                        lore(line("auth.admin.action.lock.lore"))));
                        set(SLOT_UNLOCK, !locked ? fillerPane()
                                        : named(Items.EMERALD, Lang.plain(viewer(), "auth.admin.action.unlock.name")
                                                        .formatted(Formatting.GREEN),
                                                        lore(line("auth.admin.action.unlock.lore"))));
                        set(SLOT_FORCE_LOGOUT, authed
                                        ? named(Items.REDSTONE, Lang.plain(viewer(), "auth.admin.action.forcelogout.name")
                                                        .formatted(Formatting.YELLOW),
                                                        lore(line("auth.admin.action.forcelogout.lore")))
                                        : fillerPane());
                        set(SLOT_RESET_HINT, named(Items.PAPER,
                                        Lang.plain(viewer(), "auth.admin.action.reset.name").formatted(Formatting.LIGHT_PURPLE),
                                        lore(line("auth.admin.action.reset.lore1"), line("auth.admin.action.reset.lore2"))));
                        set(SLOT_BACK, named(Items.ARROW,
                                        Lang.plain(viewer(), "auth.admin.action.back.name").formatted(Formatting.GRAY)));

                        fill();
                }

                @Override
                protected void onClick(int slot) {
                        ServerPlayerEntity admin = viewer();
                        if (!isAdmin(admin)) {
                                admin.closeHandledScreen();
                                return;
                        }
                        String targetName = target.getGameProfile().name();
                        String targetNorm = net.secureauth.account.AccountRepository.normalize(targetName);
                        switch (slot) {
                                case SLOT_LOCK -> setLocked(admin, true);
                                case SLOT_UNLOCK -> setLocked(admin, false);
                                case SLOT_FORCE_LOGOUT -> {
                                        AuthSession session = manager.session(target);
                                        if (session != null && session.authenticated()) {
                                                manager.logout(target);
                                                manager.logger().log(SecurityEvent.ADMIN_FORCE_LOGOUT,
                                                                admin.getGameProfile().name(), targetNorm,
                                                                admin.getIp(), "panel");
                                                manager.sendTranslated(admin, "auth.admin.forcelogout.success", targetName);
                                        }
                                        refresh();
                                }
                                case SLOT_RESET_HINT -> {
                                        manager.sendTranslated(admin, "auth.admin.action.reset.hint", targetName);
                                        refresh();
                                }
                                case SLOT_BACK -> AdminPanel.open(manager, admin);
                                default -> {
                                        // informational
                                }
                        }
                }

                private void setLocked(ServerPlayerEntity admin, boolean lock) {
                        AuthSession session = manager.session(target);
                        Account account = session == null ? null : session.account;
                        if (account == null) {
                                manager.sendTranslated(admin, "auth.admin.unknownPlayer", target.getGameProfile().name());
                                return;
                        }
                        try {
                                manager.repository().setLocked(account.id(), lock);
                        } catch (StoreException e) {
                                // Root cause into the logs (since 1.2.4): a generic player-facing
                                // message alone made flaky store failures undiagnosable.
                                manager.logger().log(SecurityEvent.DATABASE_UNAVAILABLE,
                                                admin.getGameProfile().name(), null, admin.getIp(),
                                                "panel_lock:" + net.secureauth.account.StoreException.describe(e));
                                manager.sendTranslated(admin, "auth.storage.unavailable");
                                return;
                        }
                        account.setLocked(lock);
                        account.setLockoutUntil(0);
                        account.setFailedAttempts(0);
                        if (session != null) {
                                if (session.account != null) {
                                        session.account.setLocked(lock);
                                        session.account.setLockoutUntil(0);
                                        session.account.setFailedAttempts(0);
                                }
                                if (lock && !session.authenticated()) {
                                        session.state = AuthState.LOCKED;
                                } else if (!lock && session.state == AuthState.LOCKED) {
                                        session.state = AuthState.REGISTERED_NOT_AUTHENTICATED;
                                }
                                manager.sendAuthPrompt(session);
                        }
                        manager.logger().log(lock ? SecurityEvent.ACCOUNT_PERMANENTLY_LOCKED
                                        : SecurityEvent.ACCOUNT_UNLOCKED,
                                        admin.getGameProfile().name(), account.usernameNorm(), admin.getIp(),
                                        "panel");
                        manager.sendTranslated(admin, lock ? "auth.admin.lock.success" : "auth.admin.unlock.success",
                                        account.usernameDisplay());
                        refresh();
                }

                /** Admin gate re-checked per click: the same check as /auth panel. */
                private boolean isAdmin(ServerPlayerEntity admin) {
                        int level = Math.min(4, Math.max(1, manager.config().administration.adminOpLevel));
                        try {
                                return admin.hasPermissionLevel(level);
                        } catch (RuntimeException e) {
                                return false;
                        }
                }

                @Override
                protected void onClickSpam() {
                        manager.logger().log(SecurityEvent.INVALID_AUTH_PACKET, viewer().getGameProfile().name(),
                                        viewer().getIp(), "admin_detail_click_spam");
                }

                @Override
                public Text title() {
                        return Lang.plain(viewer(), "auth.admin.detail.title", target.getGameProfile().name());
                }
        }
}
