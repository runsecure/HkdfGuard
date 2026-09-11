using System.Security.Cryptography;
using System.Text;
using HkdfGuard.Core.Primitives;
using HkdfGuard.DataProtectionKey.Diagnostics;
using HkdfGuard.DataProtectionKey.KeyTracking;
using HkdfGuard.Abstractions;

namespace HkdfGuard.DataProtectionKey.Protector;

/// <summary>
/// Default IDataProtector. Internal: only KeyRing (KeyRing.CreateProtector) can construct one, so
/// callers only ever see it as an IDataProtector - guaranteeing every instance is actually bound
/// to a real KeyRing rather than constructed loose. name is converted once to an
/// IAdditionalAuthData and used for every Encrypt/Decrypt, so a value protected under one
/// name/purpose fails to decrypt under another. Encrypt resolves keyRing.GetCurrent() fresh on
/// every call rather than capturing a version once at construction, so it always protects new
/// data with whatever the ring's latest rotation is; Decrypt instead resolves whichever version
/// the formatted ciphertext itself names, so old versions stay readable regardless.
/// </summary>
internal sealed class DataProtector(
    string name,
    KeyRing keyRing,
    IEncryptedFormatProvider formatProvider) : IDataProtector
{
    private readonly IAdditionalAuthData _aad = new AdditionalAuthData(name.AsSpan());

    /// <inheritdoc/>
    public string Encrypt(ReadOnlySpan<char> plaintext)
    {
        using var activity = DataProtectionDiagnostics.ActivitySource.StartActivity("DataProtector.Encrypt");
        if (DataProtectionDiagnostics.EnableSensitiveLogging)
            DataProtectionDiagnostics.LogSensitiveOperation(activity, "DataProtector.Encrypt",
                ("name", name), ("plaintextLength", plaintext.Length));

        try
        {
            var (version, key) = keyRing.GetCurrent();

            var plaintextBytes = new byte[Encoding.UTF8.GetByteCount(plaintext)];
            Encoding.UTF8.GetBytes(plaintext, plaintextBytes);

            // plaintextBytes is zeroed as a side effect of the Encrypt call it's passed to.
            var encryptedBytes = key.Encrypt(plaintextBytes, _aad);

            return formatProvider.Format(new KeyTrackingValue
            {
                KeyVersion = version,
                Value = encryptedBytes
            });
        }
        catch (Exception ex)
        {
            DataProtectionDiagnostics.RecordException(activity, ex);
            throw;
        }
    }

    /// <inheritdoc/>
    public int Decrypt(ReadOnlySpan<char> encrypted, Span<char> result)
    {
        using var activity = DataProtectionDiagnostics.ActivitySource.StartActivity("DataProtector.Decrypt");
        if (DataProtectionDiagnostics.EnableSensitiveLogging)
            DataProtectionDiagnostics.LogSensitiveOperation(activity, "DataProtector.Decrypt",
                ("name", name), ("encryptedLength", encrypted.Length));

        try
        {
            var value = formatProvider.Parse(encrypted);
            var key = keyRing.Get(value.KeyVersion);

            // AEAD ciphertext is always at least as long as the plaintext it encloses, so
            // value.Value.Length is a safe upper bound for the decrypted UTF8 byte count.
            var plaintextBytes = new byte[value.Value.Length];
            try
            {
                var bytesWritten = key.Decrypt(value.Value, _aad, plaintextBytes);
                return Encoding.UTF8.GetChars(plaintextBytes.AsSpan(0, bytesWritten), result);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintextBytes);
            }
        }
        catch (Exception ex)
        {
            DataProtectionDiagnostics.RecordException(activity, ex);
            throw;
        }
    }

    /// <inheritdoc/>
    public int GetMaxDecryptedLength(ReadOnlySpan<char> encrypted)
        => formatProvider.GetMaxDecryptedLength(encrypted);
}
