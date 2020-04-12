const std = @import("std");
const heap = std.heap;
const io = std.io;
const mem = std.mem;
const testing = std.testing;

/// A scanner reads tokens from a stream. Tokens are byte slices delimited by a set of possible bytes.
/// The BufferSize must be big enough to hold a single token
///
/// For example, here's how to scan for lines:
///
///  var line_scanner = Scanner(...).init(in_stream, "\n");
///  while (try line_scanner.scan()) {
///    var token = line_scanner.token();
///  }
///
/// The token is only valid for a single scan call: if you want to keep it you need to duplicate it.
pub fn Scanner(comptime InStreamType: type, comptime BufferSize: comptime_int) type {
    return struct {
        const Self = @This();

        allocator: *mem.Allocator,

        in_stream: InStreamType,
        delimiter_bytes: []const u8,

        previous_buffer: [BufferSize]u8,
        previous_buffer_slice: []u8,

        buffer: [BufferSize]u8,
        buffer_slice: []u8,

        remaining: usize,

        token: []const u8,

        pub fn init(allocator: *mem.Allocator, in_stream: InStreamType, delimiter_bytes: []const u8) Self {
            return Self{
                .allocator = allocator,
                .in_stream = in_stream,
                .delimiter_bytes = delimiter_bytes,
                .previous_buffer = undefined,
                .previous_buffer_slice = &[_]u8{},
                .buffer = undefined,
                .buffer_slice = &[_]u8{},
                .remaining = 0,
                .token = undefined,
            };
        }

        fn refill(self: *Self) !void {
            const n = try self.in_stream.readAll(&self.buffer);
            self.buffer_slice = self.buffer[0..n];
            self.remaining = n;
        }

        fn isSplitByte(self: Self, c: u8) bool {
            for (self.delimiter_bytes) |b| {
                if (b == c) {
                    return true;
                }
            }
            return false;
        }

        /// Get the current token if any.
        /// If there is no previous succcessful call to `scan` the token returned is undefined memory.
        pub fn getToken(self: Self) []const u8 {
            return self.token;
        }

        /// Scans for the next token.
        /// Returns true if a token is found, false otherwise.
        ///
        /// The token can be obtained with `getToken()`.
        /// The token is only valid for a single call, if you want
        /// to keep a reference to it you need to duplicate it.
        pub fn scan(self: *Self) !bool {
            comptime var i = 0;

            // Only need two iterations because we only have 2 buffers.
            // If we would continue to loop we would lose data starting from the 3 iteration.
            //
            // We _could_ have multiple buffers to solve that but there's not much point when
            // it's just easier to simply increase the buffer size.

            inline while (i < 2) : (i += 1) {
                if (self.remaining == 0) _ = try self.refill();
                if (self.remaining <= 0) return false;

                var j: usize = 0;
                while (j < self.buffer_slice.len) : (j += 1) {
                    self.remaining -= 1;

                    if (self.isSplitByte(self.buffer_slice[j])) {
                        // Only allocate a new string if the previous buffer is non empty.
                        const line = if (self.previous_buffer_slice.len > 0)
                            try mem.concat(self.allocator, u8, &[_][]const u8{
                                self.previous_buffer_slice,
                                self.buffer_slice[0..j],
                            })
                        else
                            self.buffer_slice[0..j];

                        mem.set(u8, &self.previous_buffer, 0);
                        self.previous_buffer_slice = &[_]u8{};
                        self.buffer_slice = self.buffer_slice[j + 1 .. self.buffer_slice.len];

                        self.token = line;
                        return true;
                    }
                }

                mem.copy(u8, &self.previous_buffer, self.buffer_slice);
                self.previous_buffer_slice = self.previous_buffer[0..self.buffer_slice.len];
                self.buffer_slice = &[_]u8{};
            }

            return false;
        }
    };
}

fn testScanner(comptime BufferSize: comptime_int) !void {
    var arena = heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const data = "foobar\nhello\rbonjour\x00";
    var fbs = io.fixedBufferStream(data);
    var in_stream = fbs.inStream();

    var scanner = Scanner(@TypeOf(in_stream), BufferSize).init(&arena.allocator, in_stream, "\r\n\x00");

    testing.expect(try scanner.scan());
    testing.expectEqualSlices(u8, "foobar", scanner.getToken());

    testing.expect(try scanner.scan());
    testing.expectEqualSlices(u8, "hello", scanner.getToken());

    testing.expect(try scanner.scan());
    testing.expectEqualSlices(u8, "bonjour", scanner.getToken());

    testing.expect((try scanner.scan()) == false);
}

test "line scanner: scan" {
    try testScanner(8);
    try testScanner(50);
    try testScanner(1024);
}
