const std = @import("std");
const Args = @import("Args");
const dhcp = @import("dhcp");

pub fn handle_packet_type(
    io: std.Io,
    args: Args,
    bootp_header: *dhcp.BootpHeader,
    param_req_list_options: *dhcp.DHCPOptions,
    server: Server,
    resp_type: dhcp.DHCPPacketType,
) !void {

    // if we get a discover packet we build an OFFER packet
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

    var offer_buf: [300]u8 = undefined;

    param_req_list_options.lease_duration = args.lease_duration;
    param_req_list_options.pkt_type = resp_type;
    param_req_list_options.server_addr = args.server_addr;
    param_req_list_options.server_addr = args.lease_gw;

    var dhcp_packet = dhcp.DHCPPacket.init(bootp_header, param_req_list_options);
    try dhcp_packet.write_to_buf(&offer_buf);

    try std.Io.net.Socket.send(&server.socket, io, &server.broadcast_addr, offer_buf[0..300]);

    std.log.info("{s} sent to {x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}", .{
        @tagName(resp_type),
        bootp_header.chaddr[0],
        bootp_header.chaddr[1],
        bootp_header.chaddr[2],
        bootp_header.chaddr[3],
        bootp_header.chaddr[4],
        bootp_header.chaddr[5],
    });
}

pub const Server = struct {
    socket: std.Io.net.Socket,
    broadcast_addr: std.Io.net.IpAddress,

    pub fn init(io: std.Io, addr: []const u8, args: Args) !Server {
        const ip = try std.Io.net.IpAddress.parseIp4(addr, 67);
        const socket = try ip.bind(io, .{ .protocol = .udp, .mode = .dgram, .allow_broadcast = true });
        const broadcast_ip = try dhcp.compute_broadcast_from_cidr_and_ip(args.lease_cidr, args.server_addr);
        const broadcast_addr = std.Io.net.IpAddress{ .ip4 = .{ .bytes = broadcast_ip, .port = 68 } };

        return .{ .socket = socket, .broadcast_addr = broadcast_addr };
    }
};

pub fn main(init: std.process.Init) !void {
    const args = try Args.parse(init);
    const io = init.io;

    var recv_buffer: [1024]u8 = undefined;

    const server = try Server.init(io, "0.0.0.0", args);

    if (args.verbose) {
        std.log.info("broadcast address: {d}.{d}.{d}.{d}/{}", .{ server.broadcast_addr.ip4.bytes[0], server.broadcast_addr.ip4.bytes[1], server.broadcast_addr.ip4.bytes[2], server.broadcast_addr.ip4.bytes[3], args.lease_cidr });
        std.log.info("server addr: {d}.{d}.{d}.{d}", .{ args.server_addr[0], args.server_addr[1], args.server_addr[2], args.server_addr[3] });
        std.log.info("lease addr: {d}.{d}.{d}.{d}  gw: {d}.{d}.{d}.{d}  duration: {}s", .{
            args.lease_addr[0],  args.lease_addr[1], args.lease_addr[2], args.lease_addr[3],
            args.lease_gw[0],    args.lease_gw[1],   args.lease_gw[2],   args.lease_gw[3],
            args.lease_duration,
        });
    }

    std.log.info("tiny-dhcp server listening...", .{});

    while (true) {
        const msg = try server.socket.receive(io, &recv_buffer);
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

        var received_dhcp_options = try dhcp.DHCPOptions.init_from_incoming_dhcp_packet(msg.data[dhcp.DHCP_OPTIONS_OFFSET..]);

        const received_pkt: dhcp.DHCPPacket = .init(&bootp_header, &received_dhcp_options);

        var param_req_list_options: dhcp.DHCPOptions = undefined;

        if (received_dhcp_options.parameter_request_list) |list| {
            param_req_list_options = dhcp.DHCPOptions.init_from_param_request_list(list, args);
        }

        if (received_pkt.bootp_header.op == dhcp.BOOTP_OP_REQUEST) {
            bootp_header.op = dhcp.BOOTP_OP_REPLY;
            bootp_header.siaddr = &args.server_addr;
            bootp_header.yiaddr = &args.lease_addr;
            bootp_header.ciaddr = &[_]u8{ 0, 0, 0, 0 };

            if (args.verbose) std.log.info("DHCP message type: {s}", .{@tagName(received_pkt.dhcp_options.pkt_type.?)});

            switch (received_pkt.dhcp_options.pkt_type.?) {
                .DISCOVER => {
                    try handle_packet_type(io, args, &bootp_header, &param_req_list_options, server, .OFFER);
                },
                .REQUEST => {
                    try handle_packet_type(io, args, &bootp_header, &param_req_list_options, server, .ACK);
                },
                else => {
                    std.log.warn("dhcp packet type not supported: {d}", .{received_dhcp_options.pkt_type.?});
                },
            }
        }
    }
}
