using HkdfGuard.Core.Interop;

namespace HkdfGuard.Core.Test;

public class MacKeyChainStorageTests
{
    private const string ServiceName = "HkdfGuard.Core.Test";

    [Fact]
    public void CreateOrGet_PersistsAndReturnsSameMaterial()
    {
        if (!OperatingSystem.IsMacOS())
            return; // Backed by the macOS Keychain; only exercised on macOS.

        var storage = new MacKeyChainStorage(ServiceName);
        var index = $"{ServiceName}.{Guid.NewGuid()}";

        try
        {
            var first = new byte[32];
            var second = new byte[32];

            var written = storage.CreateOrGet(index, first);
            storage.CreateOrGet(index, second);

            Assert.Equal(32, written);
            Assert.NotEqual(new byte[32], first); // Confirms real material was actually written back.
            Assert.Equal(first, second);
        }
        finally
        {
            storage.Delete(index);
        }
    }

    [Fact]
    public void Delete_RemovesStoredMaterial()
    {
        if (!OperatingSystem.IsMacOS())
            return;

        var storage = new MacKeyChainStorage(ServiceName);
        var index = $"{ServiceName}.{Guid.NewGuid()}";

        var original = new byte[32];
        storage.CreateOrGet(index, original);

        storage.Delete(index);

        var afterDelete = new byte[32];
        try
        {
            storage.CreateOrGet(index, afterDelete);

            Assert.NotEqual(original, afterDelete);
        }
        finally
        {
            storage.Delete(index);
        }
    }

    [Fact]
    public void CreateOrGet_WithEmptyIndex_Throws()
    {
        if (!OperatingSystem.IsMacOS())
            return;

        var storage = new MacKeyChainStorage(ServiceName);

        Assert.Throws<ArgumentNullException>(() => storage.CreateOrGet(string.Empty, new byte[32]));
    }

    [Fact]
    public void CreateOrGet_WithWrongSizedBuffer_Throws()
    {
        if (!OperatingSystem.IsMacOS())
            return;

        var storage = new MacKeyChainStorage(ServiceName);
        var index = $"{ServiceName}.{Guid.NewGuid()}";

        Assert.Throws<ArgumentException>(() => storage.CreateOrGet(index, new byte[16]));
    }

    [Fact]
    public void Dispose_DoesNotThrow()
    {
        if (!OperatingSystem.IsMacOS())
            return;

        var storage = new MacKeyChainStorage(ServiceName);

        var exception = Record.Exception(storage.Dispose);

        Assert.Null(exception);
    }
}
