const std = @import("std");
const uv = @import("libuv");

pub fn main() !void {
    std.debug.print("Starting TCP server...\n", .{});

    var loop = try uv.Loop.init(std.heap.page_allocator);
    defer loop.deinit(std.heap.page_allocator);
}