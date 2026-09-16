using HkdfGuard.Abstractions;

namespace HkdfGuard.DataProtectionKey.Test.TestHelpers;

/// <summary>
/// An IKeyWrapper that always reveals the same fixed key, tracking how many times Decrypt was
/// called - isolates KeyWrappedDataProtectionKey/KeyRing tests from the real blob/file/OS-storage
/// machinery (already covered by HkdfGuard.Core.Test) while still exercising real AES-GCM via
/// a real ISymmetricCipher.
/// </summary>
internal sealed class FakeKeyWrapper(byte[] key) : IKeyWrapper
{
    public int DecryptCallCount { get; private set; }

    /// <summary>
    /// When set, Decrypt throws this instead of revealing the key - lets tests exercise a
    /// KeyWrappedDataProtectionKey Encrypt/Decrypt catch block without depending on the real
    /// cipher failing.
    /// </summary>
    public Exception? ThrowOnDecrypt { get; set; }

    public int Decrypt(Span<byte> result)
    {
        DecryptCallCount++;
        if (ThrowOnDecrypt is not null)
            throw ThrowOnDecrypt;

        key.CopyTo(result);
        return key.Length;
    }

    public int Decrypt(IAdditionalAuthData aad, Span<byte> result)
        => Decrypt(result);
}
