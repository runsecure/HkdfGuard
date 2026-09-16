using HkdfGuard.Core.Diagnostics;
using HkdfGuard.Core.Primitives;
using HkdfGuard.Core.Utilities;
using HkdfGuard.Abstractions;

namespace HkdfGuard.Core.Cryptography;

/// <summary>
/// Reveals the key protected by an already-validated key blob (see KeyBlobFactory.TryLoad) - the
/// blob's signature is checked once, before this wrapper is ever constructed, not on every
/// Decrypt call. Wrapping/protecting a key is IKeyProtector's job (see KeyProtector), not this
/// class's.
/// </summary>
public class HkdfKeyWrapper(IKeyDerivationFunction keyDerivation,
    ISymmetricCipher cipher,
    IKeyBlob blob,
    int materialIdentifier,
    int iterations,
    string serviceName)
 : IKeyWrapper
{
    /// <inheritdoc/>
    public int Decrypt(Span<byte> result)
        => Decrypt(AdditionalAuthData.Empty, result);

    /// <inheritdoc/>
    public int Decrypt(IAdditionalAuthData aad, Span<byte> result)
    {
        using var activity = HkdfDiagnostics.ActivitySource.StartActivity("HkdfKeyWrapper.Decrypt");
        if (HkdfDiagnostics.EnableSensitiveLogging)
            HkdfDiagnostics.LogSensitiveOperation(activity, "HkdfKeyWrapper.Decrypt",
                ("serviceName", serviceName), ("aadLength", aad.AsSpan().Length));

        Span<byte> key = stackalloc byte[32];
        try
        {
            keyDerivation.Derive(blob.EncryptedKeySalt, blob.Salt, materialIdentifier, iterations, serviceName, key);
            return cipher.Decrypt(key, blob.EncryptedKeyValue, aad, result);
        }
        catch (Exception ex)
        {
            HkdfDiagnostics.RecordException(activity, ex);
            throw;
        }
        finally
        {
            ArrayUtility.ZeroMemory(key);
        }
    }
}
