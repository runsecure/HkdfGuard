using System.Security.Cryptography;
using HkdfGuard.Abstractions;
using HkdfGuard.Core.Diagnostics;
using HkdfGuard.Core.Primitives;
using HkdfGuard.Core.Utilities;

namespace HkdfGuard.Core.Cryptography;

/// <summary>
/// A minimal IKeyProtector for first-time initialization, before any protected key blob exists.
/// Unlike HkdfKeyWrapper, it derives its wrapping key using a caller-supplied salt (paired with
/// the spec's own materialIdentifier/iterations), rather than loading them from an existing
/// IKeyBlob. It only protects (Encrypt) - there is nothing yet to reveal, so it does not
/// implement IKeyWrapper's Decrypt. Constructed directly from an IKeySpec + salt - there is no
/// factory indirection, since nothing about minting one varies beyond those two inputs.
/// </summary>
public class KeyProtector(IKeySpec spec, byte[] salt) : IKeyProtector
{
    /// <inheritdoc/>
    public int Encrypt(Span<byte> plaintext, Span<byte> result)
        => Encrypt(plaintext, AdditionalAuthData.Empty, result);

    /// <inheritdoc/>
    public int Encrypt(Span<byte> plaintext, IAdditionalAuthData aad, Span<byte> result)
    {
        using var activity = HkdfDiagnostics.ActivitySource.StartActivity("KeyProtector.Encrypt");
        if (HkdfDiagnostics.EnableSensitiveLogging)
            HkdfDiagnostics.LogSensitiveOperation(activity, "KeyProtector.Encrypt",
                ("serviceName", spec.ServiceName), ("plaintextLength", plaintext.Length), ("aadLength", aad.AsSpan().Length));

        Span<byte> key = stackalloc byte[32];
        try
        {
            if (ArrayUtility.IsNullOrEmpty(plaintext))
                throw new ArgumentException("Plaintext must not be empty or all zero.", nameof(plaintext));

            var nonce = result.Slice(0, 32);
            RandomNumberGenerator.Fill(nonce);
            spec.KeyDerivation.Derive(nonce, salt, spec.MaterialIdentifier, spec.Iterations, spec.ServiceName, key);
            return spec.Cipher.Encrypt(key, plaintext, aad, result.Slice(32, result.Length - 32)) + 32;
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
