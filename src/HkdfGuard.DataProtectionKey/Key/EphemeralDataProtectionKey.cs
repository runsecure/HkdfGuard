using System.Security.Cryptography;
using HkdfGuard.Abstractions;
using HkdfGuard.Core.Cryptography;
using HkdfGuard.Core.Primitives;
using HkdfGuard.DataProtectionKey.Diagnostics;

namespace HkdfGuard.DataProtectionKey.Key;

/// <summary>
/// An IDataProtectionKey whose own key is never read from a file on disk - it's generated once,
/// lazily on first use, and protected into an in-memory IKeyBlob that lives only for this
/// instance's lifetime. Key derivation still goes through the same IKeySpec/IKeyInputStorage a
/// durable, file-backed key would use (the caller supplies a normally-configured IKeySpec, e.g.
/// via CryptoRecipeBuilder backed by KeyInputStorageFactory) - the only difference from
/// KeyWrappedDataProtectionKey is that nothing here is ever written to or read from disk.
/// </summary>
public sealed class EphemeralDataProtectionKey(
    IKeySpec keySpec,
    IKeyWrapperFactory keyWrapperFactory,
    KeyBlobSpec? blobSpec = null) : IDataProtectionKey
{
    private static readonly KeyBlobSpec DefaultBlobSpec = new(
        saltLength: 64, encryptedKeySaltLength: 32, encryptedKeyValueLength: 60, signatureLength: 64);

    private readonly Lazy<IDataProtectionKey> _inner = new(
        () => CreateInner(keySpec, keyWrapperFactory, blobSpec ?? DefaultBlobSpec),
        LazyThreadSafetyMode.ExecutionAndPublication);

    private static IDataProtectionKey CreateInner(
        IKeySpec keySpec, IKeyWrapperFactory keyWrapperFactory, KeyBlobSpec blobSpec)
    {
        using var activity = DataProtectionDiagnostics.ActivitySource.StartActivity("EphemeralDataProtectionKey.Initialize");
        try
        {
            Span<byte> plaintextKey = stackalloc byte[32];
            RandomNumberGenerator.Fill(plaintextKey);

            var salt = RandomNumberGenerator.GetBytes(blobSpec.SaltLength);
            var protector = new KeyProtector(keySpec, salt);

            // Built and signed entirely in memory - never saved to or loaded from a file.
            var blob = KeyBlobFactory.Create(plaintextKey, protector, keySpec, blobSpec, salt);
            var wrapper = keyWrapperFactory.Create(keySpec, blob);

            return new KeyWrappedDataProtectionKey(wrapper, keySpec.Cipher);
        }
        catch (Exception ex)
        {
            DataProtectionDiagnostics.RecordException(activity, ex);
            throw;
        }
    }

    /// <inheritdoc/>
    public byte[] Encrypt(Span<byte> plaintext)
        => _inner.Value.Encrypt(plaintext);

    /// <inheritdoc/>
    public byte[] Encrypt(Span<byte> plaintext, IAdditionalAuthData aad)
        => _inner.Value.Encrypt(plaintext, aad);

    /// <inheritdoc/>
    public int Decrypt(ReadOnlySpan<byte> ciphertext, Span<byte> result)
        => _inner.Value.Decrypt(ciphertext, result);

    /// <inheritdoc/>
    public int Decrypt(ReadOnlySpan<byte> ciphertext, IAdditionalAuthData aad, Span<byte> result)
        => _inner.Value.Decrypt(ciphertext, aad, result);
}
