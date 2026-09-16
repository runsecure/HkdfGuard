namespace HkdfGuard.Initializer.Test.TestHelpers;

/// <summary>
/// A throwaway directory under the OS temp path, deleted on Dispose - for tests that need real
/// key files on disk for InitializerApp to read, protect, and write back.
/// </summary>
internal sealed class TempDirectory : IDisposable
{
    public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"hkdfguard-init-test-{Guid.NewGuid():N}");

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
