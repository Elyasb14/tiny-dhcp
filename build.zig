const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});

    const optimize = b.standardOptimizeOption(.{});

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    const dhcp_mod = b.createModule(.{
        .root_source_file = b.path("src/dhcp.zig"),
        .target = target,
        .optimize = optimize,
    });

    const args_mod = b.createModule(.{
        .root_source_file = b.path("src/Args.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{
        .name = "tiny-dhcp",
        .root_module = exe_mod,
    });

    dhcp_mod.addImport("Args", args_mod);
    exe.root_module.addImport("dhcp", dhcp_mod);
    exe.root_module.addImport("Args", args_mod);
    b.installArtifact(exe);

    const test_exe = b.addTest(.{ .root_module = dhcp_mod });
    const test_run = b.addRunArtifact(test_exe);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&test_run.step);
}
