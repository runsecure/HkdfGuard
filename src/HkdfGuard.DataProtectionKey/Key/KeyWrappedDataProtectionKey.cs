using HkdfGuard.Core.Primitives;
using HkdfGuard.Core.Utilities;
using HkdfGuard.DataProtectionKey.Diagnostics;
using HkdfGuard.Abstractions;

namespace HkdfGuard.DataProtectionKey.Key;

/// <summary>
/// An IDataProtectionKey backed by one independently protected key file. keyWrapper reveals that
/// file's own embedded key (Salt + EncryptedKeySalt + EncryptedKeyValue) fresh on every
/// operation - never held beyond a stack-allocated span, zeroed immediately after use - and
/// cipher then performs the actual data encrypt/decrypt with it.
/// </summary>
public class KeyWrappedDataProtectionKey(
    IKeyWrapper keyWrapper,
    ISymmetricCipher cipher) : IDataProtectionKey
{
    private const int KeyLength = 32;

    // ISymmetricCipher is cipher-agnostic, so its exact ciphertext overhead (nonce/tag for
    // AES-GCM, potentially something else for a swapped-in cipher) isn't known here - over-
    // allocate generously and trim to what it actually wrote.
    private const int MaxCipherOverhead = 64;

    /// <inheritdoc/>
    public byte[] Encrypt(Span<byte> plaintext)
        => Encrypt(plaintext, AdditionalAuthData.Empty);

    /// <inheritdoc/>
    public byte[] Encrypt(Span<byte> plaintext, IAdditionalAuthData aad)
    {
        using var activity = DataProtectionDiagnostics.ActivitySource.StartActivity("KeyWrappedDataProtectionKey.Encrypt");
        if (DataProtectionDiagnostics.EnableSensitiveLogging)
            DataProtectionDiagnostics.LogSensitiveOperation(activity, "KeyWrappedDataProtectionKey.Encrypt",
                ("plaintextLength", plaintext.Length), ("aadLength", aad.AsSpan().Length));

        Span<byte> key = stackalloc byte[KeyLength];
        try
        {
            keyWrapper.Decrypt(key);

            var buffer = new byte[plaintext.Length + MaxCipherOverhead];
            var written = cipher.Encrypt(key, plaintext, aad, buffer);
            return buffer.AsSpan(0, written).ToArray();
        }
        catch (Exception ex)
        {
            DataProtectionDiagnostics.RecordException(activity, ex);
            throw;
        }
        finally
        {
            ArrayUtility.ZeroMemory(key);
        }
    }

    /// <inheritdoc/>
    public int Decrypt(ReadOnlySpan<byte> ciphertext, Span<byte> result)
        => Decrypt(ciphertext, AdditionalAuthData.Empty, result);

    /// <inheritdoc/>
    public int Decrypt(ReadOnlySpan<byte> ciphertext, IAdditionalAuthData aad, Span<byte> result)
    {
        using var activity = DataProtectionDiagnostics.ActivitySource.StartActivity("KeyWrappedDataProtectionKey.Decrypt");
        if (DataProtectionDiagnostics.EnableSensitiveLogging)
            DataProtectionDiagnostics.LogSensitiveOperation(activity, "KeyWrappedDataProtectionKey.Decrypt",
                ("ciphertextLength", ciphertext.Length), ("aadLength", aad.AsSpan().Length));

        Span<byte> key = stackalloc byte[KeyLength];
        try
        {
            keyWrapper.Decrypt(key);
            return cipher.Decrypt(key, ciphertext, aad, result);
        }
        catch (Exception ex)
        {
            DataProtectionDiagnostics.RecordException(activity, ex);
            throw;
        }
        finally
        {
            ArrayUtility.ZeroMemory(key);
        }
    }
}
