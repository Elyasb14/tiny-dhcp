const std = @import("std");
const Args = @import("Args.zig");
const dhcp = @import("dhcp");

pub fn main(init: std.process.Init) !void {
    const args = try Args.parse(init);
    const io = init.io;

    const addr = try std.Io.net.IpAddress.parseIp4("0.0.0.0", 67);

    var server = try addr.bind(io, .{ .protocol = .udp, .mode = .dgram, .allow_broadcast = true });
    var recv_buffer: [1024]u8 = undefined;

    const bcast_ip = try dhcp.compute_broadcast_from_cidr_and_ip(args.lease_cidr, args.server_addr);
    const broadcast_addr = std.Io.net.IpAddress{ .ip4 = .{ .bytes = bcast_ip, .port = 68 } };

    if (args.verbose) {
        std.log.info("broadcast address: {d}.{d}.{d}.{d}/{}", .{ bcast_ip[0], bcast_ip[1], bcast_ip[2], bcast_ip[3], args.lease_cidr });
        std.log.info("server addr: {d}.{d}.{d}.{d}", .{ args.server_addr[0], args.server_addr[1], args.server_addr[2], args.server_addr[3] });
        std.log.info("lease addr: {d}.{d}.{d}.{d}  gw: {d}.{d}.{d}.{d}  duration: {}s", .{
            args.lease_addr[0],  args.lease_addr[1], args.lease_addr[2], args.lease_addr[3],
            args.lease_gw[0],    args.lease_gw[1],   args.lease_gw[2],   args.lease_gw[3],
            args.lease_duration,
        });
    }

    std.log.info("tiny-dhcp server listening...", .{});

    while (true) {
        const msg = try server.receive(io, &recv_buffer);
        if (msg.data.len < 240) {
            if (args.verbose) std.log.info("ignored short packet ({d} bytes)", .{msg.data.len});
            continue;
        }

        var bootp_header = dhcp.BootpHeader.init(msg.data);

        if (!std.mem.eql(u8, msg.data[236..240], &dhcp.DHCP_MAGIC_COOKIE)) {
            std.log.debug("not a dhcp packet...", .{});
            continue;
        }

        if (args.verbose) {
            std.log.info("received DHCP packet: {d} bytes  xid=0x{x:0>2}{x:0>2}{x:0>2}{x:0>2}  chaddr={x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}", .{
                msg.data.len,
                msg.data[4],
                msg.data[5],
                msg.data[6],
                msg.data[7],
                msg.data[28],
                msg.data[29],
                msg.data[30],
                msg.data[31],
                msg.data[32],
                msg.data[33],
            });
        }

        var i: usize = dhcp.DHCP_OPTIONS_OFFSET;
        while (i < msg.data.len) {
            const op = msg.data[i];
            if (op == 0) {
                i += 1;
                continue;
            }

            if (op == 255) break;
            if (i + 1 >= msg.data.len) break;

            const len = msg.data[i + 1];
            const value_end = i + 2 + len;
            if (value_end > msg.data.len) break;

            const data = msg.data[i + 2 .. value_end];
            if (op == 53) {
                bootp_header.op = dhcp.BOOTP_OP_REPLY;
                bootp_header.siaddr = &args.server_addr;
                bootp_header.yiaddr = &args.lease_addr;
                bootp_header.ciaddr = &[_]u8{ 0, 0, 0, 0 };

                if (data.len >= 1) {
                    const dhcp_packet_type: dhcp.DHCPPacketType = std.enums.fromInt(dhcp.DHCPPacketType, data[0]) orelse {
                        std.log.warn("dhcp packet type not supported: {d}", .{data[0]});
                        break;
                    };

                    if (args.verbose) std.log.info("DHCP message type: {s}", .{@tagName(dhcp_packet_type)});

                    // TODO: we want to construct a dhcp packet from the client, currently the DHCPPacket is desgined to be constructed with bespoke values
                    // from command line args and whatever we want a DHCPOptions struct eventually and we pass that to the DHCPPacket
                    // also we want to be able to parse out the clients requested values and send stuff based on that, right now what we have is fine tho

                    switch (dhcp_packet_type) {
                        .DISCOVER => {
                            if (args.verbose) {
                                std.log.info("building OFFER for {x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2} -> yiaddr={d}.{d}.{d}.{d}  gw={d}.{d}.{d}.{d}  server={d}.{d}.{d}.{d}  lease={}s  cidr={}", .{
                                    bootp_header.chaddr[0], bootp_header.chaddr[1], bootp_header.chaddr[2],
                                    bootp_header.chaddr[3], bootp_header.chaddr[4], bootp_header.chaddr[5],
                                    args.lease_addr[0],     args.lease_addr[1],     args.lease_addr[2],
                                    args.lease_addr[3],     args.lease_gw[0],       args.lease_gw[1],
                                    args.lease_gw[2],       args.lease_gw[3],       args.server_addr[0],
                                    args.server_addr[1],    args.server_addr[2],    args.server_addr[3],
                                    args.lease_duration,    args.lease_cidr,
                                });
                            }

                            // if we get a discover packet we build an OFFER packet
                            var offer_buf: [300]u8 = undefined;

                            var dhcp_options: dhcp.DHCPOptions = .{
                                .lease_duration = args.lease_duration,
                                .dhcp_packet_type = .OFFER,
                                .lease_cidr = args.lease_cidr,
                                .server_addr = args.server_addr,
                                .lease_gw = args.lease_gw,
                            };

                            var dhcp_packet = dhcp.DHCPPacket.init(&bootp_header, &dhcp_options);
                            try dhcp_packet.write_to_buf(&offer_buf);

                            try std.Io.net.Socket.send(&server, io, &broadcast_addr, offer_buf[0..300]);

                            std.log.info("OFFER SENT", .{});
                        },
                        .REQUEST => {
                            if (args.verbose) {
                                std.log.info("building ACK for {x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2} -> yiaddr={d}.{d}.{d}.{d}  gw={d}.{d}.{d}.{d}  server={d}.{d}.{d}.{d}  lease={}s  cidr={}", .{
                                    bootp_header.chaddr[0], bootp_header.chaddr[1], bootp_header.chaddr[2],
                                    bootp_header.chaddr[3], bootp_header.chaddr[4], bootp_header.chaddr[5],
                                    args.lease_addr[0],     args.lease_addr[1],     args.lease_addr[2],
                                    args.lease_addr[3],     args.lease_gw[0],       args.lease_gw[1],
                                    args.lease_gw[2],       args.lease_gw[3],       args.server_addr[0],
                                    args.server_addr[1],    args.server_addr[2],    args.server_addr[3],
                                    args.lease_duration,    args.lease_cidr,
                                });
                            }

                            // if we get a request packet we build an ACK packet
                            var ack_buf: [300]u8 = undefined;

                            var dhcp_options: dhcp.DHCPOptions = .{
                                .lease_duration = args.lease_duration,
                                .dhcp_packet_type = .ACK,
                                .lease_cidr = args.lease_cidr,
                                .server_addr = args.server_addr,
                                .lease_gw = args.lease_gw,
                            };

                            var dhcp_packet = dhcp.DHCPPacket.init(&bootp_header, &dhcp_options);
                            try dhcp_packet.write_to_buf(&ack_buf);

                            try std.Io.net.Socket.send(&server, io, &broadcast_addr, ack_buf[0..300]);

                            std.log.info("ACK SENT", .{});
                        },
                        else => {
                            std.log.warn("dhcp packet type not supported: {d}", .{dhcp_packet_type});
                        },
                    }
                }
            }

            i = value_end;
        }
    }
}
