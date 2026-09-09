using System.Security.Cryptography;
using HkdfGuard.Abstractions;
using HkdfGuard.Core.Diagnostics;
using HkdfGuard.Core.Primitives;
using HkdfGuard.Core.Utilities;

namespace HkdfGuard.Core.Cryptography;

/// <summary>
/// A minimal IKeyProtector for first-time initialization, before any protected key blob exists.
/// Unlike HkdfKeyWrapper, it derives its wrapping key using a caller-supplied
/// salt/materialIdentifier/iterations, rather than loading them from an existing IKeyBlob.
/// It only protects (Encrypt) - there is nothing yet to reveal, so it does not implement
/// IKeyWrapper's Decrypt.
/// </summary>
public class KeyProtector(
    IKeyDerivationFunction keyDerivation,
    ISymmetricCipher cipher,
    byte[] salt,
    int materialIdentifier,
    int iterations,
    string serviceName) : IKeyProtector
{
    public int Encrypt(Span<byte> plaintext, Span<byte> result)
        => Encrypt(plaintext, AdditionalAuthData.Empty, result);

    public int Encrypt(Span<byte> plaintext, IAdditionalAuthData aad, Span<byte> result)
    {
        using var activity = HkdfDiagnostics.ActivitySource.StartActivity("KeyProtector.Encrypt");
        if (HkdfDiagnostics.EnableSensitiveLogging)
            HkdfDiagnostics.LogSensitiveOperation(activity, "KeyProtector.Encrypt",
                ("serviceName", serviceName), ("plaintextLength", plaintext.Length), ("aadLength", aad.AsSpan().Length));

        Span<byte> key = stackalloc byte[32];
        try
        {
            if (ArrayUtility.IsNullOrEmpty(plaintext))
                throw new ArgumentException("Plaintext must not be empty or all zero.", nameof(plaintext));

            var nonce = result.Slice(0, 32);
            RandomNumberGenerator.Fill(nonce);
            keyDerivation.Derive(nonce, salt, materialIdentifier, iterations, serviceName, key);
            return cipher.Encrypt(key, plaintext, result.Slice(32, result.Length - 32)) + 32;
        }
        catch (Exception ex)
        {
            HkdfDiagnostics.RecordException(activity, ex);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }
}
