using HkdfGuard.Core.Interop;

namespace HkdfGuard.Core.Test;

// Pure in-memory ConcurrentDictionary wrapper with no OS dependency, despite living in the Linux-
// specific Interop namespace (it's LinuxSystemdStorage's own bookkeeping) - safe to test on any OS.
public class LinuxKeyRingTrackerTests
{
    [Fact]
    public void TryGetValue_ForUnknownIndex_ReturnsFalse()
    {
        var index = $"unknown-{Guid.NewGuid()}";

        var found = LinuxKeyRingTracker.TryGetValue(index, out var value);

        Assert.False(found);
        Assert.Equal(0, value);
    }

    [Fact]
    public void AddOrUpdateThenTryGetValue_RoundTrips()
    {
        var index = $"index-{Guid.NewGuid()}";

        LinuxKeyRingTracker.AddOrUpdate(index, 42);
        var found = LinuxKeyRingTracker.TryGetValue(index, out var value);

        Assert.True(found);
        Assert.Equal(42, value);
    }

    [Fact]
    public void AddOrUpdate_CalledTwiceWithSameIndex_OverwritesPreviousValue()
    {
        var index = $"index-{Guid.NewGuid()}";

        LinuxKeyRingTracker.AddOrUpdate(index, 1);
        LinuxKeyRingTracker.AddOrUpdate(index, 2);
        LinuxKeyRingTracker.TryGetValue(index, out var value);

        Assert.Equal(2, value);
    }
}
