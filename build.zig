const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const libuv_dep = b.dependency("libuv", .{});
    const libuv_module = libuv_dep.module("libuv");

    const exe = b.addExecutable(.{
        .name = "zig-libp2p",
        .root_source_file = .{ .cwd_relative = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });

    exe.root_module.addImport("libuv", libuv_module);
    exe.linkLibC();
    exe.linkSystemLibrary("libuv");

    b.installArtifact(exe);

    // Add run step
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}