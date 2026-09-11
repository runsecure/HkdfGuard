using HkdfGuard.Abstractions;

namespace HkdfGuard.Cache.AwsSecretsManager.Test.TestHelpers;

/// <summary>
/// An IKeyWrapper that always reveals the same fixed key - isolates AwsSecretsManagerProtectedCache
/// tests from the real blob/file/OS-storage machinery (already covered elsewhere) while still
/// exercising real AES-GCM via a real ISymmetricCipher.
/// </summary>
internal sealed class FakeKeyWrapper(byte[] key) : IKeyWrapper
{
    public int Decrypt(Span<byte> result)
    {
        key.CopyTo(result);
        return key.Length;
    }

    public int Decrypt(IAdditionalAuthData aad, Span<byte> result)
        => Decrypt(result);
}
