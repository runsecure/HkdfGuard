using System.Text;
using HkdfGuard.Abstractions;
using HkdfGuard.DataProtectionKey.KeyTracking;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Primitives;

namespace HkdfGuard.EncryptedConfiguration;

/// <summary>
/// Default IProtectedConfigurationRoot. Delegates every IConfigurationRoot member to the
/// wrapped root unchanged, and reveals configuration values formatted as protected secrets via
/// an IDataProtector bound to the given KeyRing. Configuration itself only ever holds formatted
/// ciphertext strings - Decrypt reveals fresh from the underlying root on every call rather
/// than caching anything, so a Reload takes effect immediately.
/// </summary>
public sealed class ProtectedConfigurationRoot(IConfigurationRoot configurationRoot, KeyRing keyRing)
    : IProtectedConfigurationRoot
{
    /// <summary>
    /// Used as this instance's IDataProtector's Additional Auth Data, binding every value this
    /// class decrypts to this specific purpose.
    /// </summary>
    public const string ProtectorName = "HkdfGuard.EncryptedConfiguration";

    private readonly IDataProtector _protector = keyRing.CreateProtector(ProtectorName);

    /// <inheritdoc cref="IConfiguration"/>
    public string? this[string key]
    {
        get => configurationRoot[key];
        set => configurationRoot[key] = value;
    }

    /// <inheritdoc/>
    public IEnumerable<IConfigurationProvider> Providers => configurationRoot.Providers;

    /// <inheritdoc/>
    public void Reload() => configurationRoot.Reload();

    /// <inheritdoc/>
    public IConfigurationSection GetSection(string key) => configurationRoot.GetSection(key);

    /// <inheritdoc/>
    public IEnumerable<IConfigurationSection> GetChildren() => configurationRoot.GetChildren();

    /// <inheritdoc/>
    public IChangeToken GetReloadToken() => configurationRoot.GetReloadToken();

    /// <inheritdoc/>
    public int Decrypt(string name, Span<char> result)
    {
        using var activity = EncryptedConfigurationDiagnostics.ActivitySource.StartActivity("ProtectedConfigurationRoot.Decrypt");
        if (EncryptedConfigurationDiagnostics.EnableSensitiveLogging)
            EncryptedConfigurationDiagnostics.LogSensitiveOperation(activity, "ProtectedConfigurationRoot.Decrypt", ("name", name));

        try
        {
            var value = configurationRoot[name];
            if (value is null)
                return 0;

            return _protector.Decrypt(value, result);
        }
        catch (Exception ex)
        {
            EncryptedConfigurationDiagnostics.RecordException(activity, ex);
            throw;
        }
    }

    /// <inheritdoc/>
    public int Decrypt(string name, Span<byte> result)
    {
        using var activity = EncryptedConfigurationDiagnostics.ActivitySource.StartActivity("ProtectedConfigurationRoot.Decrypt");
        if (EncryptedConfigurationDiagnostics.EnableSensitiveLogging)
            EncryptedConfigurationDiagnostics.LogSensitiveOperation(activity, "ProtectedConfigurationRoot.Decrypt", ("name", name));

        try
        {
            var value = configurationRoot[name];
            if (value is null)
                return 0;

            // The format provider's max-length bound is computed from the ciphertext's own byte
            // length, so it's a safe upper bound for the decrypted plaintext's UTF8 byte count
            // too, not just its char count.
            var charBuffer = new char[_protector.GetMaxDecryptedLength(value)];
            try
            {
                var charsWritten = _protector.Decrypt(value, charBuffer);
                return Encoding.UTF8.GetBytes(charBuffer.AsSpan(0, charsWritten), result);
            }
            finally
            {
                charBuffer.AsSpan().Clear();
            }
        }
        catch (Exception ex)
        {
            EncryptedConfigurationDiagnostics.RecordException(activity, ex);
            throw;
        }
    }

    /// <inheritdoc/>
    public bool TryGetMaxDecryptedLength(string name, out int maxLength)
    {
        var value = configurationRoot[name];
        if (value is null)
        {
            maxLength = 0;
            return false;
        }

        maxLength = _protector.GetMaxDecryptedLength(value);
        return true;
    }
}
