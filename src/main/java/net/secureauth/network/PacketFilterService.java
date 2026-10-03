package net.secureauth.network;

import com.mojang.brigadier.tree.CommandNode;
import com.mojang.brigadier.builder.LiteralArgumentBuilder;
import com.mojang.brigadier.tree.RootCommandNode;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import net.minecraft.command.CommandSource;
import net.minecraft.component.DataComponentTypes;
import net.minecraft.component.type.MapIdComponent;
import net.minecraft.entity.player.PlayerInventory;
import net.minecraft.item.FilledMapItem;
import net.minecraft.item.ItemStack;
import net.minecraft.item.map.MapDecoration;
import net.minecraft.item.map.MapState;
import net.minecraft.network.packet.Packet;
import net.minecraft.network.packet.s2c.common.CustomPayloadS2CPacket;
import net.minecraft.network.packet.s2c.play.ChatMessageS2CPacket;
import net.minecraft.network.packet.s2c.play.CommandTreeS2CPacket;
import net.minecraft.network.packet.s2c.play.GameMessageS2CPacket;
import net.minecraft.network.packet.s2c.play.MapUpdateS2CPacket;
import net.minecraft.network.packet.s2c.play.PlayerListHeaderS2CPacket;
import net.minecraft.network.packet.s2c.play.PlayerListS2CPacket;
import net.minecraft.network.packet.s2c.play.PlayerRemoveS2CPacket;
import net.minecraft.network.packet.s2c.play.ProfilelessChatMessageS2CPacket;
import net.minecraft.network.packet.s2c.play.ScoreboardDisplayS2CPacket;
import net.minecraft.network.packet.s2c.play.ScoreboardObjectiveUpdateS2CPacket;
import net.minecraft.network.packet.s2c.play.TeamS2CPacket;
import net.minecraft.scoreboard.ScoreboardDisplaySlot;
import net.minecraft.scoreboard.ScoreboardObjective;
import net.minecraft.scoreboard.ServerScoreboard;
import net.minecraft.scoreboard.Team;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.command.CommandManager;
import net.minecraft.server.network.ServerCommonNetworkHandler;
import net.minecraft.server.network.ServerPlayNetworkHandler;
import net.minecraft.server.network.ServerPlayerEntity;
import net.minecraft.world.World;
import net.secureauth.auth.AuthManager;
import net.secureauth.auth.AuthSession;

/**
 * Pre-authentication world-information isolation.
 *
 * <p>Complements dimension isolation: while a player is unauthenticated, the
 * server drops packets that would leak real-world information from the
 * broadcast stream to that specific viewer — other players' tab-list entries,
 * chat/join/leave broadcasts, map data, (optionally) scoreboards and other
 * mods' custom payloads. SecureAuth's own packets are exempt via
 * {@link PacketBypass}.</p>
 */
public final class PacketFilterService {

        private final AuthManager authManager;

        public PacketFilterService(AuthManager authManager) {
                this.authManager = authManager;
        }

        // ------------------------------------------------------------------
        // Outgoing filter (called from the packet-send mixin)
        // ------------------------------------------------------------------

        /**
         * Decides whether {@code packet} must be dropped for the connection
         * {@code listener}. Fail-closed: unknown states never authenticate.
         */
        public boolean shouldDrop(ServerCommonNetworkHandler listener, Packet<?> packet) {
                if (PacketBypass.isBypassed()) {
                        return false;
                }
                if (!(listener instanceof ServerPlayNetworkHandler gameHandler)) {
                        return false;
                }
                ServerPlayerEntity viewer = gameHandler.player;
                if (viewer == null) {
                        return false;
                }
                AuthSession session = authManager.session(viewer);
                if (session == null || session.authenticated()) {
                        return false;
                }

                var info = authManager.config().worldInfo;

                if (packet instanceof PlayerListS2CPacket || packet instanceof PlayerRemoveS2CPacket) {
                        return info.hideTabList;
                }
                if (packet instanceof PlayerListHeaderS2CPacket) {
                        return info.hideTabList;
                }
                if (packet instanceof GameMessageS2CPacket
                                || packet instanceof ChatMessageS2CPacket
                                || packet instanceof ProfilelessChatMessageS2CPacket) {
                        return info.suppressChatBroadcasts;
                }
                if (packet instanceof MapUpdateS2CPacket) {
                        return info.hideMaps;
                }
                if (packet instanceof ScoreboardObjectiveUpdateS2CPacket || packet instanceof ScoreboardDisplayS2CPacket) {
                        return info.filterScoreboard;
                }
                if (packet instanceof CustomPayloadS2CPacket) {
                        return info.filterCustomPayloads;
                }
                return false;
        }

        // ------------------------------------------------------------------
        // Tab list control
        // ------------------------------------------------------------------

        /** Removes all other players from an unauthenticated viewer's tab list. */
        public void hideOtherPlayers(ServerPlayerEntity viewer, MinecraftServer server) {
                List<UUID> others = new ArrayList<>();
                for (ServerPlayerEntity online : server.getPlayerManager().getPlayerList()) {
                        if (!online.getUuid().equals(viewer.getUuid())) {
                                others.add(online.getUuid());
                        }
                }
                if (others.isEmpty()) {
                        return;
                }
                PacketBypass.run(() -> viewer.networkHandler.sendPacket(new PlayerRemoveS2CPacket(others)));
        }

        /**
         * Re-adds every online player to a freshly authenticated viewer's tab list.
         *
         * <p>Since 1.2.3 this sends exactly the packet vanilla sends to a joining
         * player ({@code createPlayerInitializing}: ADD_PLAYER + UPDATE_LISTED +
         * gamemode/latency/display-name/hat). A tab entry is only <em>rendered</em>
         * when its "listed" bit is set; the previous ADD_PLAYER-only re-add left
         * the entries present but unlisted, so the player's tab list stayed empty
         * until the next full rejoin — the "player has to rejoin to get the tab
         * back" report.</p>
         */
        public void restoreOtherPlayers(ServerPlayerEntity viewer, MinecraftServer server) {
                PacketBypass.run(() -> viewer.networkHandler.sendPacket(PlayerListS2CPacket
                                .entryFromPlayer(server.getPlayerManager().getPlayerList())));
        }

        /**
         * Re-sends the server's scoreboard state (teams + every displayed
         * objective) to a freshly authenticated viewer, mirroring vanilla's
         * join-time sync. Objectives created while the viewer was quarantined
         * had their packets dropped by the filter; without this re-sync they
         * would only appear on the next scoreboard change.
         */
        public void restoreScoreboard(ServerPlayerEntity viewer, MinecraftServer server) {
                try {
                        ServerScoreboard scoreboard = server.getScoreboard();
                        PacketBypass.run(() -> {
                                for (Team team : scoreboard.getTeams()) {
                                        viewer.networkHandler.sendPacket(TeamS2CPacket
                                                        .updateTeam(team, true));
                                }
                                Set<ScoreboardObjective> synced = new HashSet<>();
                                for (ScoreboardDisplaySlot slot : ScoreboardDisplaySlot.values()) {
                                        ScoreboardObjective objective = scoreboard.getObjectiveForSlot(slot);
                                        if (objective == null || !synced.add(objective)) {
                                                continue;
                                        }
                                        for (Packet<?> packet : scoreboard.createChangePackets(objective)) {
                                                viewer.networkHandler.sendPacket(packet);
                                        }
                                }
                        });
                } catch (RuntimeException e) {
                        // Cosmetic re-sync; it must never break the auth flow.
                        authManager.logger().log(net.secureauth.security.SecurityEvent.CONFIG_ERROR,
                                        viewer.getGameProfile().getName(), "scoreboard_restore_failed");
                }
        }

        /**
         * Re-sends the full data of every map item the freshly authenticated
         * viewer carries. The vanilla sender marks dropped map packets as
         * delivered, so held maps would otherwise stay blank until their data
         * changes again (the "idk about maps" gap).
         */
        public void resendMapData(ServerPlayerEntity viewer) {
                if (!authManager.config().worldInfo.hideMaps) {
                        return; // maps were never filtered for this viewer
                }
                try {
                        PlayerInventory inventory = viewer.getInventory();
                        World level = viewer.getWorld();
                        for (int slot = 0; slot < inventory.size(); slot++) {
                                ItemStack stack = inventory.getStack(slot);
                                if (stack.isEmpty()) {
                                        continue;
                                }
                                MapIdComponent mapId = stack.get(DataComponentTypes.MAP_ID);
                                if (mapId == null) {
                                        continue;
                                }
                                MapState data = FilledMapItem.getMapState(stack, level);
                                if (data == null) {
                                        continue;
                                }
                                List<MapDecoration> decorations = new ArrayList<>();
                                for (MapDecoration decoration : data.getDecorations()) {
                                        decorations.add(decoration);
                                }
                                MapState.UpdateData fullPatch = new MapState.UpdateData(
                                                0, 0, 128, 128, data.colors);
                                PacketBypass.run(() -> viewer.networkHandler.sendPacket(new MapUpdateS2CPacket(
                                                mapId, data.scale, data.locked,
                                                Optional.of(decorations), Optional.of(fullPatch))));
                        }
                } catch (RuntimeException e) {
                        // Cosmetic re-sync; it must never break the auth flow.
                        authManager.logger().log(net.secureauth.security.SecurityEvent.CONFIG_ERROR,
                                        viewer.getGameProfile().getName(), "map_data_restore_failed");
                }
        }

        // ------------------------------------------------------------------
        // Command tree minimisation
        // ------------------------------------------------------------------

        /**
         * Replaces the client's command tree with one containing only the
         * authentication commands, so no server command names leak pre-auth.
         */
        public void sendMinimalCommandTree(ServerPlayerEntity viewer) {
                try {
                        RootCommandNode<CommandSource> root = new RootCommandNode<>();
                        addLiteral(root, "register");
                        addLiteral(root, "login");
                        addLiteral(root, "authpanel");
                        addLiteral(root, "auth");
                        PacketBypass.run(() -> viewer.networkHandler.sendPacket(
                                        new CommandTreeS2CPacket(root)));
                } catch (Exception e) {
                        // Worst case: the full tree stays visible; command blocking is
                        // enforced server-side regardless.
                        authManager.logger().log(net.secureauth.security.SecurityEvent.CONFIG_ERROR,
                                        viewer.getGameProfile().getName(), "minimal_command_tree_failed");
                }
        }

        /** Restores the player's real, permission-filtered command tree. */
        public void restoreCommandTree(ServerPlayerEntity viewer) {
                try {
                        PacketBypass.run(() -> viewer.getWorld().getServer().getCommandManager().sendCommandTree(viewer));
                } catch (Exception e) {
                        // Vanilla resends the tree on permission change/relog anyway.
                }
        }

        @SuppressWarnings({"unchecked", "rawtypes"})
        private static void addLiteral(RootCommandNode<CommandSource> root, String name) {
                LiteralArgumentBuilder builder = CommandManager.literal(name);
                CommandNode node = builder.build();
                root.addChild((CommandNode<CommandSource>) node);
        }
}