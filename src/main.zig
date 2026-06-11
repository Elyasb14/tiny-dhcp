const std = @import("std");
const Args = @import("Args.zig");

fn cidr_to_subnet_mask(cidr: u8) ![4]u8 {
    if (cidr > 32) return error.InvalidCidr;
    const mask_u32: u32 = if (cidr == 0) 0 else (@as(u32, 0xFFFFFFFF) << @intCast(32 - cidr));

    return .{
        @intCast((mask_u32 >> 24) & 0xFF),
        @intCast((mask_u32 >> 16) & 0xFF),
        @intCast((mask_u32 >> 8) & 0xFF),
        @intCast(mask_u32 & 0xFF),
    };
}

pub const DHCPPacketType = enum(u8) {
    DISCOVER = 1,
    OFFER = 2,
    REQUEST = 3,
    ACK = 5,
};

pub const DHCPPacket = struct {
    bootp_header: *BootpHeader,
    dhcp_type: DHCPPacketType,
    lease_duration: u32,
    cidr: u8,
    gw: [4]u8,
    server_id: [4]u8,

    pub fn init(bootp_header: *BootpHeader, lease_duration: u32, dhcp_type: DHCPPacketType, cidr: u8, gw: [4]u8, server_id: [4]u8) DHCPPacket {
        return .{ .bootp_header = bootp_header, .lease_duration = lease_duration, .dhcp_type = dhcp_type, .cidr = cidr, .gw = gw, .server_id = server_id };
    }

    pub fn write_to_buf(self: *DHCPPacket, out: []u8) !void {
        @memset(out, 0);

        var ld_as_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &ld_as_bytes, self.lease_duration, .big);

        const subnet_mask = try cidr_to_subnet_mask(self.cidr);

        if (out.len < 268) return error.BufferTooSmall;

        out[0] = self.bootp_header.op;
        out[1] = self.bootp_header.htype;
        out[2] = self.bootp_header.hlen;
        out[3] = self.bootp_header.hops;

        @memcpy(out[4..8], self.bootp_header.xid_be);
        @memcpy(out[8..10], self.bootp_header.secs_be);
        @memcpy(out[10..12], self.bootp_header.flags_be);
        @memcpy(out[12..16], self.bootp_header.ciaddr);
        @memcpy(out[16..20], self.bootp_header.yiaddr);
        @memcpy(out[20..24], self.bootp_header.siaddr);
        @memcpy(out[24..28], self.bootp_header.giaddr);
        @memcpy(out[28..44], self.bootp_header.chaddr);
        @memcpy(out[44..108], self.bootp_header.sname);
        @memcpy(out[108..236], self.bootp_header.file);
        @memcpy(out[236..240], &DHCP_MAGIC_COOKIE);

        // dhcp message type
        out[240] = 53;
        out[241] = 1;
        out[242] = @intFromEnum(self.dhcp_type);

        // server ip
        out[243] = 54;
        out[244] = 4;
        out[245] = self.server_id[0];
        out[246] = self.server_id[1];
        out[247] = self.server_id[2];
        out[248] = self.server_id[3];

        // set subnet mask
        out[249] = 1;
        out[250] = 4;
        out[251] = subnet_mask[0];
        out[252] = subnet_mask[1];
        out[253] = subnet_mask[2];
        out[254] = subnet_mask[3];

        // lease duration (i32)
        out[255] = 51;
        out[256] = 4;
        out[257] = ld_as_bytes[0];
        out[258] = ld_as_bytes[1];
        out[259] = ld_as_bytes[2];
        out[260] = ld_as_bytes[3];

        // router addr
        out[261] = 3;
        out[262] = 4;
        out[263] = self.gw[0];
        out[264] = self.gw[1];
        out[265] = self.gw[2];
        out[266] = self.gw[3];

        // end options
        out[267] = 255;
    }
};

pub const BootpHeader = struct {
    // 0..3
    op: u8,
    htype: u8,
    hlen: u8,
    hops: u8,
    // 4..11 (network byte order / big-endian)
    xid_be: []const u8,
    secs_be: []const u8,
    flags_be: []const u8,
    // 12..27
    ciaddr: []const u8,
    yiaddr: []const u8,
    siaddr: []const u8,
    giaddr: []const u8,
    // 28..235
    chaddr: []const u8,
    sname: []const u8,
    file: []const u8,

    pub fn init(buf: []u8) BootpHeader {
        return .{
            .op = buf[0],
            .htype = buf[1],
            .hlen = buf[2],
            .hops = buf[3],
            .xid_be = buf[4..8],
            .secs_be = buf[8..10],
            .flags_be = buf[10..12],
            .ciaddr = buf[12..16],
            .yiaddr = buf[16..20],
            .siaddr = buf[20..24],
            .giaddr = buf[24..28],
            .chaddr = buf[28..44],
            .sname = buf[44..108],
            .file = buf[108..236],
        };
    }
};

const BOOTP_OP_REPLY: u8 = 2;
const DHCP_OPTIONS_OFFSET: usize = 240;
const DHCP_MAGIC_COOKIE = [4]u8{ 0x63, 0x82, 0x53, 0x63 };

pub fn main(init: std.process.Init) !void {
    const args = try Args.parse(init);
    const io = init.io;

    const addr = try std.Io.net.IpAddress.parseIp4("0.0.0.0", 67);

    var server = try addr.bind(io, .{ .protocol = .udp, .mode = .dgram, .allow_broadcast = true });
    var recv_buffer: [1024]u8 = undefined;

    const broadcast_addr = try std.Io.net.IpAddress.parse("192.168.33.255", 68);

    std.log.info("tiny-dhcp server listening...", .{});

    while (true) {
        const msg = try server.receive(io, &recv_buffer);
        if (msg.data.len < 240) continue;

        var bootp_header = BootpHeader.init(msg.data);

        if (!std.mem.eql(u8, msg.data[236..240], &DHCP_MAGIC_COOKIE)) {
            std.log.debug("not a dhcp packet...", .{});
            continue;
        }

        var i: usize = DHCP_OPTIONS_OFFSET;
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
                bootp_header.op = BOOTP_OP_REPLY;
                bootp_header.yiaddr = &args.lease_addr;
                bootp_header.siaddr = &args.server_addr;
                bootp_header.ciaddr = &[_]u8{ 0, 0, 0, 0 };

                if (data.len >= 1) {
                    const dhcp_packet_type: DHCPPacketType = @enumFromInt(data[0]);

                    switch (dhcp_packet_type) {
                        .DISCOVER => {
                            // if we get a discover packet we build an OFFER packet
                            var offer_buf: [300]u8 = undefined;

                            var dhcp_packet = DHCPPacket.init(&bootp_header, args.lease_duration, .OFFER, args.lease_cidr, args.lease_gw, args.server_addr);
                            try dhcp_packet.write_to_buf(&offer_buf);

                            try std.Io.net.Socket.send(&server, io, &broadcast_addr, offer_buf[0..268]);

                            std.log.info("OFFER SENT", .{});
                        },
                        .REQUEST => {
                            // if we get a request packet we build an ACK packet
                            var ack_buf: [300]u8 = undefined;

                            var dhcp_packet = DHCPPacket.init(&bootp_header, args.lease_duration, .ACK, args.lease_cidr, args.lease_gw, args.server_addr);
                            try dhcp_packet.write_to_buf(&ack_buf);

                            try std.Io.net.Socket.send(&server, io, &broadcast_addr, ack_buf[0..268]);

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
