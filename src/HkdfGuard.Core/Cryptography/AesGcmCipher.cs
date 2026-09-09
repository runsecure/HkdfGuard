using System.Security.Cryptography;
using HkdfGuard.Core.Diagnostics;
using HkdfGuard.Core.Primitives;
using HkdfGuard.Core.Utilities;
using HkdfGuard.Abstractions;

namespace HkdfGuard.Core.Cryptography;

public class AesGcmCipher : ISymmetricCipher
{
    private const int TagSize = 16;
    private const int NonceSize = 12;

    public int Encrypt(Span<byte> key, Span<byte> plaintext, Span<byte> result)
        => Encrypt(key, plaintext, AdditionalAuthData.Empty, result);

    public int Encrypt(Span<byte> key, Span<byte> plaintext, IAdditionalAuthData aad, Span<byte> result)
    {
        using var activity = HkdfDiagnostics.ActivitySource.StartActivity("AesGcmCipher.Encrypt");
        if (HkdfDiagnostics.EnableSensitiveLogging)
            HkdfDiagnostics.LogSensitiveOperation(activity, "AesGcmCipher.Encrypt",
                ("plaintextLength", plaintext.Length), ("aadLength", aad.AsSpan().Length));

        try
        {
            return CoreEncrypt(key, plaintext, aad.AsSpan(), result);
        }
        catch (Exception ex)
        {
            HkdfDiagnostics.RecordException(activity, ex);
            throw;
        }
        finally
        {
            ArrayUtility.ZeroMemory(key);
            ArrayUtility.ZeroMemory(plaintext);
        }
    }

    //Pass to a separate method to convert the key to a ReadOnlySpan for the duration of encryption
    private int CoreEncrypt(ReadOnlySpan<byte> key, Span<byte> plaintext, ReadOnlySpan<byte> aad, Span<byte> result)
    {
        if (ArrayUtility.IsNullOrEmpty(key))
            throw new ArgumentException("AES key must not be empty or all zero.", nameof(key));

        if (ArrayUtility.IsNullOrEmpty(plaintext))
            throw new ArgumentException("Plaintext must not be empty or all zero.", nameof(plaintext));

        if (result.Length < NonceSize + plaintext.Length + TagSize)
            throw new ArgumentException("Result buffer too small.", nameof(result));

        // Layout: [nonce | ciphertext | tag]
        var nonce = result.Slice(0, NonceSize);
        var ciphertext = result.Slice(NonceSize, plaintext.Length);
        var tag = result.Slice(NonceSize + plaintext.Length, TagSize);

        RandomNumberGenerator.Fill(nonce);

        using var aes = new AesGcm(key, TagSize);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);

        return NonceSize + plaintext.Length + TagSize;
    }

    public int Decrypt(Span<byte> key, ReadOnlySpan<byte> ciphertext, Span<byte> result)
        => Decrypt(key, ciphertext, AdditionalAuthData.Empty, result);

    public int Decrypt(Span<byte> key, ReadOnlySpan<byte> ciphertext, IAdditionalAuthData aad, Span<byte> result)
    {
        using var activity = HkdfDiagnostics.ActivitySource.StartActivity("AesGcmCipher.Decrypt");
        if (HkdfDiagnostics.EnableSensitiveLogging)
            HkdfDiagnostics.LogSensitiveOperation(activity, "AesGcmCipher.Decrypt",
                ("ciphertextLength", ciphertext.Length), ("aadLength", aad.AsSpan().Length));

        try
        {
            return CoreDecrypt(key, ciphertext, aad.AsSpan(), result);
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
    
    //Pass to a separate method to convert the key to a ReadOnlySpan for the duration of decryption
    private int CoreDecrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> aad, Span<byte> result)
    {
        if (ArrayUtility.IsNullOrEmpty(key))
            throw new ArgumentException("AES key must not be empty or all zero.", nameof(key));

        if (ArrayUtility.IsNullOrEmpty(ciphertext))
            throw new ArgumentException("Ciphertext must not be empty or all zero.", nameof(ciphertext));

        if (ciphertext.Length < NonceSize + TagSize)
            throw new ArgumentException("Ciphertext too short.", nameof(ciphertext));

        var resultLength = ciphertext.Length - NonceSize - TagSize;

        if (result.Length < resultLength)
            throw new ArgumentException("Result buffer too small.", nameof(result));

        var nonce = ciphertext.Slice(0, NonceSize);
        var ct = ciphertext.Slice(NonceSize, resultLength);
        var tag = ciphertext.Slice(NonceSize + resultLength, TagSize);

        using var aes = new AesGcm(key, TagSize);
        aes.Decrypt(nonce, ct, tag, result.Slice(0, resultLength), aad);

        return resultLength;
    }
}
