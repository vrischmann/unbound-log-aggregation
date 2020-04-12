const std = @import("std");
const fs = std.fs;
const heap = std.heap;
const mem = std.mem;

const Scanner = @import("scanner.zig").Scanner;

const GlobalAggregatesKey = struct {
    domain_name: []const u8,
    query_type: QueryType,
};

fn eqlGlobalAggregatesKey(a: GlobalAggregatesKey, b: GlobalAggregatesKey) bool {
    return mem.eql(u8, a.domain_name, b.domain_name) and a.query_type == b.query_type;
}

const GlobalAggregates = struct {
    const Self = @This();

    const MapType = std.HashMap(
        GlobalAggregatesKey,
        usize,
        std.hash_map.getAutoHashStratFn(GlobalAggregatesKey, .DeepRecursive),
        eqlGlobalAggregatesKey,
    );

    counts: MapType,

    pub fn deinit(self: *Self) void {
        self.counts.deinit();
    }

    pub fn init(allocator: *mem.Allocator) Self {
        return Self{
            .counts = MapType.init(allocator),
        };
    }

    pub fn inc(self: *Self, line: Line) !bool {
        var result = try self.counts.getOrPut(.{
            .domain_name = line.domain_name,
            .query_type = line.query_type,
        });
        if (result.found_existing) {
            result.kv.value += 1;
            return true;
        } else {
            result.kv.value = 1;
            return false;
        }
    }
};

const QueryType = enum {
    A,
    AAAA,
};

const Line = struct {
    timestamp: u64,
    domain_name: []const u8,
    query_type: QueryType,
};

const LogLineError = error{
    OutOfMemory,
    EmptyLine,
    NoTimestampEnd,
    InvalidTimestamp,
    NoPIDEnd,
    NoDomainNamePrefix,
    NoDomainNameEnd,
    NoQueryTypeEnd,
    InvalidQueryType,
};

fn parseLine(allocator: *mem.Allocator, s: []const u8) LogLineError!Line {
    if (s.len <= 0 or s[0] != '[') return error.EmptyLine;

    var line = Line{
        .timestamp = undefined,
        .domain_name = undefined,
        .query_type = undefined,
    };

    // Parse timestamp

    const timestamp_end_index = mem.indexOfScalar(u8, s, ']');
    if (timestamp_end_index == null) {
        return error.NoTimestampEnd;
    }

    var s2 = s[1..];

    line.timestamp = std.fmt.parseInt(u64, s2[0 .. timestamp_end_index.? - 1], 10) catch |err| {
        std.debug.warn("err: {}\n", .{err});
        return error.InvalidTimestamp;
    };

    // Skip unbound pid info

    s2 = s2[timestamp_end_index.?..s2.len];

    const unbound_pid_end_index = mem.indexOfScalar(u8, s2, ']');
    if (unbound_pid_end_index == null) {
        return error.NoPIDEnd;
    }

    s2 = s2[unbound_pid_end_index.? + 2 .. s2.len];

    // Only care about lines starting with "info: resolving"

    const prefix = "info: resolving ";

    if (!mem.startsWith(u8, s2, prefix)) {
        return error.NoDomainNamePrefix;
    }

    // Get domain name

    s2 = s2[prefix.len..s2.len];

    const domain_name_end_index = mem.lastIndexOfScalar(u8, s2, '.');
    if (domain_name_end_index == null) {
        return error.NoDomainNameEnd;
    }

    line.domain_name = try mem.dupe(allocator, u8, s2[0..domain_name_end_index.?]);

    // Get query type

    s2 = s2[domain_name_end_index.? + 2 .. s2.len];

    const query_type_end_index = mem.indexOfScalar(u8, s2, ' ');
    if (query_type_end_index == null) {
        return error.NoQueryTypeEnd;
    }

    line.query_type = std.meta.stringToEnum(QueryType, s2[0..query_type_end_index.?]) orelse return error.InvalidQueryType;

    return line;
}

fn aggregationKVLessThan(lhs: GlobalAggregates.MapType.KV, rhs: GlobalAggregates.MapType.KV) bool {
    return lhs.value < rhs.value;
}

pub fn main() anyerror!void {
    var arena = heap.ArenaAllocator.init(heap.page_allocator);
    defer arena.deinit();
    const allocator = &arena.allocator;

    var args_it = std.process.args();

    if (!args_it.skip()) @panic("expected self arg");

    const file_path = try (args_it.next(allocator) orelse @panic("expected input arg"));

    const file = try fs.cwd().openFile(file_path, .{ .read = true });
    defer file.close();

    // Read line by line

    var in_stream = file.inStream();
    var line_scanner = Scanner(@TypeOf(in_stream), 1024).init(allocator, in_stream, "\n");

    var total_lines: usize = 0;
    var resolving_lines: usize = 0;

    var global_aggregates = GlobalAggregates.init(allocator);

    while (try line_scanner.scan()) {
        const token = line_scanner.token;

        total_lines += 1;

        if (mem.indexOf(u8, token, "info: resolving") == null) {
            continue;
        }

        if (parseLine(allocator, token)) |line| {
            var found_existing = try global_aggregates.inc(line);
            if (found_existing) {
                allocator.free(line.domain_name);
            }
        } else |err| {
            std.debug.warn("err: {} invalid line: {}\n", .{ err, token });
        }

        resolving_lines += 1;
    }

    std.debug.warn("lines: {} resolving lines: {}\n", .{ total_lines, resolving_lines });

    // Sort the aggregated values

    var kvs = try allocator.alloc(GlobalAggregates.MapType.KV, global_aggregates.counts.count());
    defer allocator.free(kvs);

    var iterator = global_aggregates.counts.iterator();
    var i: usize = 0;
    while (iterator.next()) |kv| {
        kvs[i] = kv.*;
        // std.debug.warn("domain name: {:<40} query type: {} count: {}\n", .{ kv.key.domain_name, kv.key.query_type, kv.value });
        i += 1;
    }

    std.sort.sort(GlobalAggregates.MapType.KV, kvs, aggregationKVLessThan);

    for (kvs) |kv| {
        std.debug.warn("domain name: {:<40} query type: {} count: {}\n", .{ kv.key.domain_name, kv.key.query_type, kv.value });
    }
}
