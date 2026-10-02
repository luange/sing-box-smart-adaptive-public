const std = @import("std");

pub fn build(b: *std.Build) void {
    // Keep artifacts portable across older VM CPU models, matching smart-engine.
    var target_query = b.standardTargetOptionsQueryOnly(.{});
    const cpu_is_implicit = std.mem.eql(u8, @tagName(target_query.cpu_model), "determined_by_cpu_arch") or
        std.mem.eql(u8, @tagName(target_query.cpu_model), "determined_by_arch_os");
    if (cpu_is_implicit) {
        target_query.cpu_model = .baseline;
    }
    const target = b.resolveTargetQuery(target_query);
    const optimize = b.standardOptimizeOption(.{});

    const lib = b.addStaticLibrary(.{
        .name = "xdp_engine",
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });
    // linux_adapter.zig uses the Linux libc socket/mmap/poll ABI.  The
    // non-Linux build selects the explicit unsupported-platform stub, so
    // linking libc remains harmless for portable policy consumers.
    lib.linkLibC();
    b.installArtifact(lib);
    b.installFile("include/xdp_engine.h", "include/xdp_engine.h");

    const tests = b.addTest(.{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });
    tests.linkLibC();
    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run next-gen XDP policy tests");
    test_step.dependOn(&run_tests.step);
}
