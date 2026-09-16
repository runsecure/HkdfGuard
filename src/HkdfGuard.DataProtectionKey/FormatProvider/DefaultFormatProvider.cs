using HkdfGuard.DataProtectionKey.Diagnostics;
using HkdfGuard.DataProtectionKey.Utilities;
using HkdfGuard.Abstractions;

namespace HkdfGuard.DataProtectionKey.FormatProvider;

public class DefaultFormatProvider : IEncryptedFormatProvider
{
    private const string EncPrefix = "enc";
    private const string Delimiter = "::";
    private const string VersionPrefix = "v";

    public string Format(KeyTrackingValue value)
    {
        using var activity = DataProtectionDiagnostics.ActivitySource.StartActivity("DefaultFormatProvider.Format");
        if (DataProtectionDiagnostics.EnableSensitiveLogging)
            DataProtectionDiagnostics.LogSensitiveOperation(activity, "DefaultFormatProvider.Format",
                ("keyVersion", value.KeyVersion), ("valueLength", value.Value.Length));

        try
        {
            var base64 = Base64ConversionUtility.ToBase64String(value.Value);
            return $"{EncPrefix}{Delimiter}{VersionPrefix}{value.KeyVersion}{Delimiter}{base64}";
        }
        catch (Exception ex)
        {
            DataProtectionDiagnostics.RecordException(activity, ex);
            throw;
        }
    }

    public KeyTrackingValue Parse(ReadOnlySpan<char> encrypted)
    {
        using var activity = DataProtectionDiagnostics.ActivitySource.StartActivity("DefaultFormatProvider.Parse");
        if (DataProtectionDiagnostics.EnableSensitiveLogging)
            DataProtectionDiagnostics.LogSensitiveOperation(activity, "DefaultFormatProvider.Parse",
                ("encryptedLength", encrypted.Length));

        try
        {
            if (!TryParseSegments(encrypted, out var version, out var base64))
                throw new FormatException(
                    $"Invalid encrypted format. Expected '{EncPrefix}{Delimiter}{VersionPrefix}<version>{Delimiter}<base64>'.");

            if (!Base64ConversionUtility.IsBase64(base64))
                throw new FormatException("Encrypted value is not valid base64.");

            var value = new byte[Base64ConversionUtility.GetBinaryLength(base64)];
            Base64ConversionUtility.FromBase64(base64, value);

            return new KeyTrackingValue
            {
                KeyVersion = version,
                Value = value
            };
        }
        catch (Exception ex)
        {
            DataProtectionDiagnostics.RecordException(activity, ex);
            throw;
        }
    }

    /// <inheritdoc/>
    public int GetMaxDecryptedLength(ReadOnlySpan<char> encrypted)
    {
        using var activity = DataProtectionDiagnostics.ActivitySource.StartActivity("DefaultFormatProvider.GetMaxDecryptedLength");
        if (DataProtectionDiagnostics.EnableSensitiveLogging)
            DataProtectionDiagnostics.LogSensitiveOperation(activity, "DefaultFormatProvider.GetMaxDecryptedLength",
                ("encryptedLength", encrypted.Length));

        try
        {
            if (!TryParseSegments(encrypted, out _, out var base64))
                throw new FormatException(
                    $"Invalid encrypted format. Expected '{EncPrefix}{Delimiter}{VersionPrefix}<version>{Delimiter}<base64>'.");

            if (!Base64ConversionUtility.IsBase64(base64))
                throw new FormatException("Encrypted value is not valid base64.");

            return Base64ConversionUtility.GetBinaryLength(base64);
        }
        catch (Exception ex)
        {
            DataProtectionDiagnostics.RecordException(activity, ex);
            throw;
        }
    }

    // Shared by Parse and GetMaxDecryptedLength so both agree on exactly what counts as
    // well-formed - only GetMaxDecryptedLength skips the actual Base64 decode/allocation.
    private static bool TryParseSegments(ReadOnlySpan<char> encrypted, out int version, out ReadOnlySpan<char> base64)
    {
        version = 0;
        base64 = default;

        var delimiter = Delimiter.AsSpan();

        var firstDelimiterIndex = encrypted.IndexOf(delimiter);
        if (firstDelimiterIndex < 0)
            return false;

        var afterPrefix = encrypted[(firstDelimiterIndex + delimiter.Length)..];
        var secondDelimiterIndex = afterPrefix.IndexOf(delimiter);
        if (secondDelimiterIndex < 0)
            return false;

        var prefix = encrypted[..firstDelimiterIndex];
        var versionSegment = afterPrefix[..secondDelimiterIndex];
        var base64Segment = afterPrefix[(secondDelimiterIndex + delimiter.Length)..];

        if (!prefix.SequenceEqual(EncPrefix) || !versionSegment.StartsWith(VersionPrefix))
            return false;

        if (!int.TryParse(versionSegment[VersionPrefix.Length..], out version))
            return false;

        base64 = base64Segment;
        return true;
    }
}
