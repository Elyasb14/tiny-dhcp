const std = @import("std");

pub const DHCPPacket = struct {
    bootp_header: *BootpHeader,
    data: []u8,

    pub fn init(bootp_header: *BootpHeader, data: []u8) DHCPPacket {
        return .{ .bootp_header = bootp_header, .data = data };
    }

    pub fn write_options(self: *DHCPPacket) void {
        self.data[240] = 53;
        self.data[241] = 1;
        self.data[242] = 2;
        self.data[243] = 54;
        self.data[244] = 4;
        self.data[245] = 192;
        self.data[246] = 168;
        self.data[247] = 33;
        self.data[248] = 4;
        self.data[249] = 1;
        self.data[250] = 4;
        self.data[251] = 255;
        self.data[252] = 255;
        self.data[253] = 255;
        self.data[254] = 0;
        self.data[255] = 51;
        self.data[256] = 4;
        self.data[257] = 0;
        self.data[258] = 0;
        self.data[259] = 0x0E;
        self.data[260] = 0x10;
        self.data[261] = 3;
        self.data[262] = 4;
        self.data[263] = 192;
        self.data[264] = 168;
        self.data[265] = 33;
        self.data[266] = 1;
        self.data[267] = 255;
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

    pub fn write_bootp_header(self: BootpHeader, out: []u8) !void {
        if (out.len < 236) return error.BufferTooSmall;

        out[0] = self.op;
        out[1] = self.htype;
        out[2] = self.hlen;
        out[3] = self.hops;

        @memcpy(out[4..8], self.xid_be);
        @memcpy(out[8..10], self.secs_be);
        @memcpy(out[10..12], self.flags_be);
        @memcpy(out[12..16], self.ciaddr);
        @memcpy(out[16..20], self.yiaddr);
        @memcpy(out[20..24], self.siaddr);
        @memcpy(out[24..28], self.giaddr);
        @memcpy(out[28..44], self.chaddr);
        @memcpy(out[44..108], self.sname);
        @memcpy(out[108..236], self.file);
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

                    try bootp_header.write_bootp_header(offer_buf[0..236]);
                    @memcpy(offer_buf[236..240], &DHCP_MAGIC_COOKIE);

                    var dhcp_packet = DHCPPacket.init(&bootp_header, &offer_buf);
                    dhcp_packet.write_options();

                    try std.Io.net.Socket.send(&server, io, &broadcast_addr, offer_buf[0..268]);

                    std.debug.print("OFFER SENT\n", .{});
                } else if (data.len >= 1 and data[0] == 3) {
                    // build ACK packet
                    var ack_buf: [300]u8 = undefined;
                    @memset(&ack_buf, 0);

                    bootp_header.op = BOOTP_OP_REPLY;
                    bootp_header.yiaddr = &[_]u8{ 192, 168, 33, 7 };
                    bootp_header.siaddr = &[_]u8{ 192, 168, 33, 4 };
                    bootp_header.ciaddr = &[_]u8{ 0, 0, 0, 0 };

                    try bootp_header.write_bootp_header(ack_buf[0..236]);
                    @memcpy(ack_buf[236..240], &DHCP_MAGIC_COOKIE);

                    var dhcp_packet = DHCPPacket.init(&bootp_header, &ack_buf);
                    dhcp_packet.write_options();

                    try std.Io.net.Socket.send(&server, io, &broadcast_addr, ack_buf[0..268]);

                    std.debug.print("ACK SENT\n", .{});
                } else {
                    std.debug.print("NOT SUPPORTED\n", .{});
                }
            }

            i = value_end;
        }
    }
}
