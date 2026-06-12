pub const std = @import("std");

pub fn cidr_to_subnet_mask(cidr: u8) ![4]u8 {
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
    dhcp_options: *DHCPOptions,

    pub fn init(bootp_header: *BootpHeader, dhcp_options: *DHCPOptions) DHCPPacket {
        return .{ .bootp_header = bootp_header, .dhcp_options = dhcp_options };
    }

    pub fn write_to_buf(self: *DHCPPacket, out: []u8) !void {
        @memset(out, 0);

        var ld_as_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &ld_as_bytes, self.dhcp_options.lease_duration.?, .big);

        const subnet_mask = try cidr_to_subnet_mask(self.dhcp_options.lease_cidr.?);

        if (out.len < 300) return error.BufferTooSmall;

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

        var slice_len: usize = 0;

        // dhcp message type
        if (self.dhcp_options.dhcp_packet_type) |dhcp_type| {
            out[240] = 53;
            out[241] = 1;
            out[242] = @intFromEnum(dhcp_type);
            slice_len += 3;
        }

        // server ip
        if (self.dhcp_options.server_addr) |addr| {
            out[243] = 54;
            out[244] = 4;
            out[245] = addr[0];
            out[246] = addr[1];
            out[247] = addr[2];
            out[248] = addr[3];
            slice_len += 6;
        }

        // set subnet mask
        out[249] = 1;
        out[250] = 4;
        out[251] = subnet_mask[0];
        out[252] = subnet_mask[1];
        out[253] = subnet_mask[2];
        out[254] = subnet_mask[3];
        slice_len += 6;

        // lease duration (i32)
        out[255] = 51;
        out[256] = 4;
        out[257] = ld_as_bytes[0];
        out[258] = ld_as_bytes[1];
        out[259] = ld_as_bytes[2];
        out[260] = ld_as_bytes[3];
        slice_len += 6;

        if (self.dhcp_options.lease_gw) |gw| {
            // router addr
            out[261] = 3;
            out[262] = 4;
            out[263] = gw[0];
            out[264] = gw[1];
            out[265] = gw[2];
            out[266] = gw[3];
            slice_len += 6;
        }

        // end options
        out[240 + slice_len] = 255;
    }
};
pub const DHCPOptions = struct {
    lease_duration: ?u32 = null,
    dhcp_packet_type: ?DHCPPacketType = null,
    lease_cidr: ?u8 = null,
    lease_gw: ?[4]u8 = null,
    server_addr: ?[4]u8 = null,
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

pub const BOOTP_OP_REPLY: u8 = 2;
pub const DHCP_OPTIONS_OFFSET: usize = 240;
pub const DHCP_MAGIC_COOKIE = [4]u8{ 0x63, 0x82, 0x53, 0x63 };

pub fn compute_broadcast_from_cidr_and_ip(cidr: u8, ip: [4]u8) ![4]u8 {
    var sm = try cidr_to_subnet_mask(cidr);
    for (sm, 0..) |x, i| {
        sm[i] = x ^ 0xff;
    }

    var broadcast_addr: [4]u8 = undefined;
    for (ip, 0..) |x, i| {
        broadcast_addr[i] = x | sm[i];
    }

    return broadcast_addr;
}
