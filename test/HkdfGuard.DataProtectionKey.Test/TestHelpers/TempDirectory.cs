namespace HkdfGuard.DataProtectionKey.Test.TestHelpers;

/// <summary>
/// A throwaway directory under the OS temp path, deleted on Dispose - for tests that need to
/// write real protected key files to disk for KeyRingBuilder/KeyBlobFactory to read back.
/// </summary>
internal sealed class TempDirectory : IDisposable
{
    public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"hkdfguard-dpk-test-{Guid.NewGuid():N}");

    public TempDirectory()
    {
        Directory.CreateDirectory(Path);
    }

    public string GetFilePath(string fileName) => System.IO.Path.Combine(Path, fileName);

    public void Dispose()
    {
        if (Directory.Exists(Path))
            Directory.Delete(Path, recursive: true);
    }
}
