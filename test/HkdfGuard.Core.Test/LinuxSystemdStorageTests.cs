using HkdfGuard.Core.Interop;

namespace HkdfGuard.Core.Test;

public class LinuxSystemdStorageTests
{
    [Fact]
    public void CreateOrGet_UsingKernelKeyring_PersistsAndReturnsSameMaterial()
    {
        if (!OperatingSystem.IsLinux())
            return; // Backed by the Linux kernel keyring; only exercised on Linux.

        // A credsDir that can never exist forces IsSystemdCredsSupported() to false, so this
        // always exercises the kernel-keyring-only path (add_key/keyctl_read) - the only path a
        // container, which should never have a real systemd managing /run/credentials, can
        // actually use. See CreateOrGet_UsingSystemdCreds_PersistsAndReturnsSameMaterial below
        // for the systemd-creds path, only exercised on a real systemd-managed Linux server.
        var storage = new LinuxSystemdStorage(credsDir: Path.Combine(Path.GetTempPath(), $"no-such-creds-dir-{Guid.NewGuid():N}"));
        var index = $"HkdfGuard.Core.Test.{Guid.NewGuid()}";

        var first = new byte[32];
        var second = new byte[32];

        var written = storage.CreateOrGet(index, first);
        storage.CreateOrGet(index, second);

        Assert.Equal(32, written);
        Assert.Equal(first, second);
    }

    [Fact]
    public void CreateOrGet_UsingSystemdCreds_PersistsAndReturnsSameMaterial()
    {
        // Only a real systemd-managed Linux server has a /run/credentials directory and a
        // working systemd-creds binary - a container (which should never run systemd itself)
        // never does, so this is skipped there. See
        // CreateOrGet_UsingKernelKeyring_PersistsAndReturnsSameMaterial above for the path every
        // Linux container can actually exercise.
        if (!OperatingSystem.IsLinux() || !Directory.Exists("/run/credentials"))
            return;

        var storage = new LinuxSystemdStorage();
        var index = $"HkdfGuard.Core.Test.{Guid.NewGuid()}";

        var first = new byte[32];
        var second = new byte[32];

        var written = storage.CreateOrGet(index, first);
        storage.CreateOrGet(index, second);

        Assert.Equal(32, written);
        Assert.Equal(first, second);
    }
}
