using HkdfGuard.Abstractions;

namespace HkdfGuard.DataProtectionKey.Test.TestHelpers;

/// <summary>
/// An IKeyProtectorFactory whose Create always throws - exercises EphemeralDataProtectionKey's
/// CreateInner catch block without depending on a specific real failure mode.
/// </summary>
internal sealed class ThrowingKeyProtectorFactory(Exception exception) : IKeyProtectorFactory
{
    public IKeyProtector Create(IKeySpec spec, byte[] salt) => throw exception;
}
