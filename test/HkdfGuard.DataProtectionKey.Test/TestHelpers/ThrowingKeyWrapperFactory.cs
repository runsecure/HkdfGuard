using HkdfGuard.Abstractions;

namespace HkdfGuard.DataProtectionKey.Test.TestHelpers;

/// <summary>
/// An IKeyWrapperFactory whose Create always throws - exercises EphemeralDataProtectionKey's
/// CreateInner catch block without depending on a specific real failure mode.
/// </summary>
internal sealed class ThrowingKeyWrapperFactory(Exception exception) : IKeyWrapperFactory
{
    public IKeyWrapper Create(IKeySpec spec, IKeyBlob blob) => throw exception;
}
