const std = @import("std");
const testing = std.testing;

pub const xev_transport = @import("xev.zig");

test {
    std.testing.refAllDeclsRecursive(@This());
}
