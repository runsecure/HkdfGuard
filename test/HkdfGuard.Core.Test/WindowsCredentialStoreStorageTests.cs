using HkdfGuard.Core.Interop;

namespace HkdfGuard.Core.Test;

public class WindowsCredentialStoreStorageTests
{
    [Fact]
    public void CreateOrGet_PersistsAndReturnsSameMaterial()
    {
        if (!OperatingSystem.IsWindows())
            return; // Backed by the Windows Credential Manager; only exercised on Windows.

        var storage = new WindowsCredentialStoreStorage();
        var index = $"HkdfGuard.Core.Test.{Guid.NewGuid()}";

        var first = new byte[32];
        var second = new byte[32];

        var written = storage.CreateOrGet(index, first);
        storage.CreateOrGet(index, second);

        Assert.Equal(32, written);
        Assert.Equal(first, second);
    }
}
