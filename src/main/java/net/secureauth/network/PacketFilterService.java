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
import net.minecraft.commands.Commands;
import net.minecraft.commands.SharedSuggestionProvider;
import net.minecraft.core.component.DataComponents;
import net.minecraft.network.protocol.Packet;
import net.minecraft.network.protocol.common.ClientboundCustomPayloadPacket;
import net.minecraft.network.protocol.game.ClientboundCommandsPacket;
import net.minecraft.network.protocol.game.ClientboundDisguisedChatPacket;
import net.minecraft.network.protocol.game.ClientboundMapItemDataPacket;
import net.minecraft.network.protocol.game.ClientboundPlayerChatPacket;
import net.minecraft.network.protocol.game.ClientboundPlayerInfoRemovePacket;
import net.minecraft.network.protocol.game.ClientboundPlayerInfoUpdatePacket;
import net.minecraft.network.protocol.game.ClientboundSetDisplayObjectivePacket;
import net.minecraft.network.protocol.game.ClientboundSetObjectivePacket;
import net.minecraft.network.protocol.game.ClientboundSetPlayerTeamPacket;
import net.minecraft.network.protocol.game.ClientboundSystemChatPacket;
import net.minecraft.network.protocol.game.ClientboundTabListPacket;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.ServerScoreboard;
import net.minecraft.server.level.ServerPlayer;
import net.minecraft.server.network.ServerCommonPacketListenerImpl;
import net.minecraft.server.network.ServerGamePacketListenerImpl;
import net.minecraft.world.entity.player.Inventory;
import net.minecraft.world.item.ItemStack;
import net.minecraft.world.item.MapItem;
import net.minecraft.world.level.Level;
import net.minecraft.world.level.saveddata.maps.MapDecoration;
import net.minecraft.world.level.saveddata.maps.MapId;
import net.minecraft.world.level.saveddata.maps.MapItemSavedData;
import net.minecraft.world.scores.DisplaySlot;
import net.minecraft.world.scores.Objective;
import net.minecraft.world.scores.PlayerTeam;
import net.secureauth.auth.AuthManager;
import net.secureauth.auth.AuthSession;

/**
 * Pre-authentication world-information isolation.
 * Complements dimension isolation: while a player is unauthenticated, the server drops packets that
 * would leak real-world information from the broadcast stream to that specific viewer — other players'
 * tab-list entries, chat/join/leave broadcasts, map data, (optionally) scoreboards and other mods'
 * custom payloads.
 * SecureAuth's own packets are exempt via PacketBypass.
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
         * Decides whether packet must be dropped for the connection listener.
         * Fail-closed: unknown states never authenticate.
         */
        public boolean shouldDrop(ServerCommonPacketListenerImpl listener, Packet<?> packet) {
                if (PacketBypass.isBypassed()) {
                        return false;
                }
                if (!(listener instanceof ServerGamePacketListenerImpl gameHandler)) {
                        return false;
                }
                ServerPlayer viewer = gameHandler.player;
                if (viewer == null) {
                        return false;
                }
                AuthSession session = authManager.session(viewer);
                if (session == null || session.authenticated()) {
                        return false;
                }

                var info = authManager.config().worldInfo;

                if (packet instanceof ClientboundPlayerInfoUpdatePacket || packet instanceof ClientboundPlayerInfoRemovePacket) {
                        return info.hideTabList;
                }
                if (packet instanceof ClientboundTabListPacket) {
                        return info.hideTabList;
                }
                if (packet instanceof ClientboundSystemChatPacket
                                || packet instanceof ClientboundPlayerChatPacket
                                || packet instanceof ClientboundDisguisedChatPacket) {
                        return info.suppressChatBroadcasts;
                }
                if (packet instanceof ClientboundMapItemDataPacket) {
                        return info.hideMaps;
                }
                if (packet instanceof ClientboundSetObjectivePacket || packet instanceof ClientboundSetDisplayObjectivePacket) {
                        return info.filterScoreboard;
                }
                if (packet instanceof ClientboundCustomPayloadPacket) {
                        return info.filterCustomPayloads;
                }
                return false;
        }

        // ------------------------------------------------------------------
        // Tab list control
        // ------------------------------------------------------------------

        /**
         * Removes all other players from an unauthenticated viewer's tab list.
         */
        public void hideOtherPlayers(ServerPlayer viewer, MinecraftServer server) {
                List<UUID> others = new ArrayList<>();
                for (ServerPlayer online : server.getPlayerList().getPlayers()) {
                        if (!online.getUUID().equals(viewer.getUUID())) {
                                others.add(online.getUUID());
                        }
                }
                if (others.isEmpty()) {
                        return;
                }
                PacketBypass.run(() -> viewer.connection.send(new ClientboundPlayerInfoRemovePacket(others)));
        }

        /**
         * Re-adds every online player to a freshly authenticated viewer's tab list.
         */
        public void restoreOtherPlayers(ServerPlayer viewer, MinecraftServer server) {
                PacketBypass.run(() -> viewer.connection.send(ClientboundPlayerInfoUpdatePacket
                                .createPlayerInitializing(server.getPlayerList().getPlayers())));
        }

        /**
         * Re-sends the server's scoreboard state (teams + every displayed objective) to a freshly
         * authenticated viewer, mirroring vanilla's join-time sync.
         * Objectives created while the viewer was quarantined had their packets dropped by the filter; without
         * this re-sync they would only appear on the next scoreboard change.
         */
        public void restoreScoreboard(ServerPlayer viewer, MinecraftServer server) {
                try {
                        ServerScoreboard scoreboard = server.getScoreboard();
                        PacketBypass.run(() -> {
                                for (PlayerTeam team : scoreboard.getPlayerTeams()) {
                                        viewer.connection.send(ClientboundSetPlayerTeamPacket
                                                        .createAddOrModifyPacket(team, true));
                                }
                                Set<Objective> synced = new HashSet<>();
                                for (DisplaySlot slot : DisplaySlot.values()) {
                                        Objective objective = scoreboard.getDisplayObjective(slot);
                                        if (objective == null || !synced.add(objective)) {
                                                continue;
                                        }
                                        for (Packet<?> packet : scoreboard.getStartTrackingPackets(objective)) {
                                                viewer.connection.send(packet);
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
         * Re-sends the full data of every map item the freshly authenticated viewer carries.
         * The vanilla sender marks dropped map packets as delivered, so held maps would otherwise stay blank
         * until their data changes again (the "idk about maps" gap).
         */
        public void resendMapData(ServerPlayer viewer) {
                if (!authManager.config().worldInfo.hideMaps) {
                        return; // maps were never filtered for this viewer
                }
                try {
                        Inventory inventory = viewer.getInventory();
                        Level level = viewer.level();
                        for (int slot = 0; slot < inventory.getContainerSize(); slot++) {
                                ItemStack stack = inventory.getItem(slot);
                                if (stack.isEmpty()) {
                                        continue;
                                }
                                MapId mapId = stack.get(DataComponents.MAP_ID);
                                if (mapId == null) {
                                        continue;
                                }
                                MapItemSavedData data = MapItem.getSavedData(stack, level);
                                if (data == null) {
                                        continue;
                                }
                                List<MapDecoration> decorations = new ArrayList<>();
                                for (MapDecoration decoration : data.getDecorations()) {
                                        decorations.add(decoration);
                                }
                                MapItemSavedData.MapPatch fullPatch = new MapItemSavedData.MapPatch(
                                                0, 0, MapItem.IMAGE_WIDTH, MapItem.IMAGE_HEIGHT, data.colors);
                                PacketBypass.run(() -> viewer.connection.send(new ClientboundMapItemDataPacket(
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
         * Replaces the client's command tree with one containing only the authentication commands, so no
         * server command names leak pre-auth.
         */
        public void sendMinimalCommandTree(ServerPlayer viewer) {
                try {
                        RootCommandNode<SharedSuggestionProvider> root = new RootCommandNode<>();
                        addLiteral(root, "register");
                        addLiteral(root, "login");
                        addLiteral(root, "authpanel");
                        addLiteral(root, "auth");
                        PacketBypass.run(() -> viewer.connection.send(
                                        new ClientboundCommandsPacket(root)));
                } catch (Exception e) {
                        // Worst case: the full tree stays visible; command blocking is
                        // enforced server-side regardless.
                        authManager.logger().log(net.secureauth.security.SecurityEvent.CONFIG_ERROR,
                                        viewer.getGameProfile().getName(), "minimal_command_tree_failed");
                }
        }

        /**
         * Restores the player's real, permission-filtered command tree.
         */
        public void restoreCommandTree(ServerPlayer viewer) {
                try {
                        PacketBypass.run(() -> viewer.level().getServer().getCommands().sendCommands(viewer));
                } catch (Exception e) {
                        // Vanilla resends the tree on permission change/relog anyway.
                }
        }

        @SuppressWarnings({"unchecked", "rawtypes"})
        private static void addLiteral(RootCommandNode<SharedSuggestionProvider> root, String name) {
                LiteralArgumentBuilder builder = Commands.literal(name);
                CommandNode node = builder.build();
                root.addChild((CommandNode<SharedSuggestionProvider>) node);
        }

}
