using HkdfGuard.Core.Interop;

namespace HkdfGuard.Core.Test;

// OperatingSystem.IsWindows/IsMacOS/IsLinux reflect the real runtime OS and can't be swapped out
// in-process, so only the branch matching the machine actually running these tests is reachable
// here - the other platform branches (and the PlatformNotSupportedException fallback) can only be
// exercised on their respective OS.
public class KeyInputStorageFactoryTests
{
    [Fact]
    public void Create_ReturnsAnImplementationForTheCurrentPlatform()
    {
        var storage = KeyInputStorageFactory.Create("HkdfGuard.Core.Test");

        Assert.NotNull(storage);
    }

    [Fact]
    public void Create_OnMacOS_ReturnsMacKeyChainStorage()
    {
        if (!OperatingSystem.IsMacOS())
            return;

        var storage = KeyInputStorageFactory.Create("HkdfGuard.Core.Test");

        Assert.IsType<MacKeyChainStorage>(storage);
    }

    [Fact]
    public void Create_OnWindows_ReturnsWindowsCredentialStoreStorage()
    {
        if (!OperatingSystem.IsWindows())
            return;

        var storage = KeyInputStorageFactory.Create("HkdfGuard.Core.Test");

        Assert.IsType<WindowsCredentialStoreStorage>(storage);
    }

    [Fact]
    public void Create_OnLinux_ReturnsLinuxSystemdStorage()
    {
        if (!OperatingSystem.IsLinux())
            return;

        var storage = KeyInputStorageFactory.Create("HkdfGuard.Core.Test");

        Assert.IsType<LinuxSystemdStorage>(storage);
    }
}
