const std = @import("std");

const Args = @This();

lease_addr: [4]u8 = .{ 192, 168, 33, 7 },
lease_duration: u32 = 50,
lease_cidr: u8 = 24,
lease_gw: [4]u8 = .{ 192, 168, 33, 1 },
server_addr: [4]u8 = .{ 192, 168, 33, 4 },
lease_dns: [4]u8 = .{ 192, 168, 33, 1 },
lease_ntp: [4]u8 = .{ 192, 168, 33, 1 },
verbose: bool = false,

pub fn parse(init: std.process.Init) !Args {
    var result: Args = .{};

    var it = try std.process.Args.Iterator.initAllocator(init.minimal.args, init.arena.allocator());
    defer it.deinit();

    const process_name = it.next() orelse "tiny-dhcp";

    while (it.next()) |arg_z| {
        const arg: []const u8 = arg_z;

        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            help(process_name);
        } else if (std.mem.eql(u8, arg, "--lease-addr")) {
            const raw = it.next() orelse {
                std.log.err("--lease-addr requires an IPv4 address", .{});
                help(process_name);
            };
            result.lease_addr = try parse_ipv4(raw);
        } else if (std.mem.eql(u8, arg, "--server-addr")) {
            const raw = it.next() orelse {
                std.log.err("--server-addr requires an IPv4 address", .{});
                help(process_name);
            };
            result.server_addr = try parse_ipv4(raw);
        } else if (std.mem.eql(u8, arg, "--lease-duration")) {
            const raw = it.next() orelse {
                std.log.err("--lease-duration requires a number of seconds", .{});
                help(process_name);
            };
            result.lease_duration = std.fmt.parseInt(u32, raw, 10) catch {
                std.log.err("invalid --lease-duration: {s}", .{raw});
                help(process_name);
            };
        } else if (std.mem.eql(u8, arg, "--lease-cidr")) {
            const raw = it.next() orelse {
                std.log.err("--lease-cidr requires an argument (0-32)", .{});
                help(process_name);
            };

            result.lease_cidr = std.fmt.parseInt(u8, raw, 10) catch {
                std.log.err("invalid --lease-cidr: {s}", .{raw});
                help(process_name);
            };
        } else if (std.mem.eql(u8, arg, "--lease-gw")) {
            const raw = it.next() orelse {
                std.log.err("--lease-gw requires an IPv4 address", .{});
                help(process_name);
            };
            result.lease_gw = try parse_ipv4(raw);
        } else if (std.mem.eql(u8, arg, "--verbose") or std.mem.eql(u8, arg, "-v")) {
            result.verbose = true;
        } else if (std.mem.eql(u8, arg, "--lease-dns")) {
            const raw = it.next() orelse {
                std.log.err("--lease-dns requires an IPv4 address", .{});
                help(process_name);
            };
            result.lease_dns = try parse_ipv4(raw);
        } else if (std.mem.eql(u8, arg, "--lease-ntp")) {
            const raw = it.next() orelse {
                std.log.err("--lease-ntp requires an IPv4 address", .{});
                help(process_name);
            };
            result.lease_ntp = try parse_ipv4(raw);
        } else {
            std.log.err("unknown option: {s}", .{arg});
            help(process_name);
        }
    }

    return result;
}

fn parse_ipv4(raw: []const u8) ![4]u8 {
    var it = std.mem.splitScalar(u8, raw, '.');
    var ip: [4]u8 = undefined;

    var idx: usize = 0;
    while (idx < 4) : (idx += 1) {
        const part = it.next() orelse return error.InvalidIp;
        ip[idx] = std.fmt.parseInt(u8, part, 10) catch return error.InvalidIp;
    }

    if (it.next() != null) return error.InvalidIp;
    return ip;
}

fn help(process_name: []const u8) noreturn {
    std.debug.print(
        \\Usage: {s} [OPTIONS]
        \\
        \\OPTIONS:
        \\  --lease-addr <ipv4>      IP to offer/ack (default: 192.168.33.7)
        \\  --server-addr <ipv4>     IP addr of dhcp server (default: 192.168.33.4)
        \\  --lease-duration <secs>  Lease time in seconds (default: 50)
        \\  --lease-cidr <0-32>      Cidr for subnet mask (default: 24)
        \\  --lease-gw <ipv4>        IP of gateway for offer/ack (default: 192.168.33.1)
        \\  --lease-dns <ipv4>       IP of dns server for offer/ack (default: 192.168.33.1)
        \\  --lease-ntp <ipv4>       IP of ntp server for offer/ack (default: 192.168.33.1)
        \\  -h, --help               Show this help message
        \\  -v, --verbose            Verbose logging
        \\
        \\EXAMPLE:
        \\  {s} --server-addr 192.168.33.4 --lease-addr 192.168.33.10 --lease-gw 192.168.33.1 --lease-duration 3600 --lease-cidr 25 --lease-dns 192.168.33.1 --lease-ntp 192.168.33.1
        \\
    , .{ process_name, process_name });
    std.process.exit(0);
}
