using HkdfGuard.Abstractions;

namespace HkdfGuard.Core.Interop;

/// <summary>
/// Creates the IKeyInputStorage implementation appropriate for the current OS. The concrete
/// storage types are internal to this assembly; this is the public entry point for consumers
/// (e.g. other executables) that need one without depending on a specific platform's type.
/// </summary>
public static class KeyInputStorageFactory
{
    /// <param name="serviceName">The service/application name used to scope stored key material (macOS Keychain service name)</param>
    /// <exception cref="PlatformNotSupportedException">The current OS has no supported IKeyInputStorage implementation</exception>
    public static IKeyInputStorage Create(string serviceName)
    {
        if (OperatingSystem.IsWindows())
            return new WindowsCredentialStoreStorage();

        if (OperatingSystem.IsMacOS())
            return new MacKeyChainStorage(serviceName);

        if (OperatingSystem.IsLinux())
            return new LinuxSystemdStorage();

        throw new PlatformNotSupportedException("No IKeyInputStorage implementation is available for this platform.");
    }
}
