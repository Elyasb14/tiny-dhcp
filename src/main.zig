const std = @import("std");

pub const DHCPPacket = struct {
    bootp_header: *BootpHeader,

    pub fn init(bootp_header: *BootpHeader) DHCPPacket {
        return .{ .bootp_header = bootp_header };
    }

    pub fn write_to_buf(self: *DHCPPacket, out: []u8) !void {
        if (out.len < 236) return error.BufferTooSmall;

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

        out[240] = 53;
        out[241] = 1;
        out[242] = 2;
        out[243] = 54;
        out[244] = 4;
        out[245] = 192;
        out[246] = 168;
        out[247] = 33;
        out[248] = 4;
        out[249] = 1;
        out[250] = 4;
        out[251] = 255;
        out[252] = 255;
        out[253] = 255;
        out[254] = 0;
        out[255] = 51;
        out[256] = 4;
        out[257] = 0;
        out[258] = 0;
        out[259] = 0x0E;
        out[260] = 0x10;
        out[261] = 3;
        out[262] = 4;
        out[263] = 192;
        out[264] = 168;
        out[265] = 33;
        out[266] = 1;
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
    const io = init.io;
    const addr = try std.Io.net.IpAddress.parse("0.0.0.0", 67);

    var server = try addr.bind(io, .{ .protocol = .udp, .mode = .dgram, .allow_broadcast = true });
    var recv_buffer: [1024]u8 = undefined;

    std.debug.print("tiny-dhcp server listening...\n", .{});

    while (true) {
        const msg = try server.receive(io, &recv_buffer);
        var bootp_header = BootpHeader.init(msg.data);

        const broadcast_addr = try std.Io.net.IpAddress.parse("255.255.255.255", 68);

        if (!std.mem.eql(u8, msg.data[236..240], &DHCP_MAGIC_COOKIE)) {
            std.debug.print("not a dhcp packet...", .{});
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
                if (data.len >= 1 and data[0] == 1) {
                    // build OFFER packet
                    var offer_buf: [300]u8 = undefined;
                    @memset(&offer_buf, 0);

                    bootp_header.op = BOOTP_OP_REPLY;
                    bootp_header.yiaddr = &[_]u8{ 192, 168, 33, 7 };
                    bootp_header.siaddr = &[_]u8{ 192, 168, 33, 4 };
                    bootp_header.ciaddr = &[_]u8{ 0, 0, 0, 0 };

                    var dhcp_packet = DHCPPacket.init(&bootp_header);
                    try dhcp_packet.write_to_buf(&offer_buf);

                    try std.Io.net.Socket.send(&server, io, &broadcast_addr, offer_buf[0..268]);

                    std.log.info("OFFER SENT", .{});
                } else if (data.len >= 1 and data[0] == 3) {
                    // build ACK packet
                    var ack_buf: [300]u8 = undefined;
                    @memset(&ack_buf, 0);

                    bootp_header.op = BOOTP_OP_REPLY;
                    bootp_header.yiaddr = &[_]u8{ 192, 168, 33, 7 };
                    bootp_header.siaddr = &[_]u8{ 192, 168, 33, 4 };
                    bootp_header.ciaddr = &[_]u8{ 0, 0, 0, 0 };

                    var dhcp_packet = DHCPPacket.init(&bootp_header);
                    try dhcp_packet.write_to_buf(&ack_buf);

                    try std.Io.net.Socket.send(&server, io, &broadcast_addr, ack_buf[0..268]);

                    std.log.info("ACK SENT", .{});
                } else {
                    std.log.err("NOT SUPPORTED", .{});
                }
            }

            i = value_end;
        }
    }
}
