using System.Security.Cryptography;
using HkdfGuard.Core.Diagnostics;
using HkdfGuard.Core.Utilities;
using HkdfGuard.Abstractions;

namespace HkdfGuard.Core.Cryptography;

public class HmacSha512Hash : IHash
{
    public const int HashSize = 64;

    /// <inheritdoc/>
    public int ComputeHash(ReadOnlySpan<byte> key, Span<byte> data, Span<byte> result)
    {
        using var activity = HkdfDiagnostics.ActivitySource.StartActivity("HmacSha512Hash.ComputeHash");
        if (HkdfDiagnostics.EnableSensitiveLogging)
            HkdfDiagnostics.LogSensitiveOperation(activity, "HmacSha512Hash.ComputeHash",
                ("dataLength", data.Length));

        try
        {
            if (ArrayUtility.IsNullOrEmpty(key))
                throw new ArgumentException("Signing key must not be empty or all zero.", nameof(key));

            if (ArrayUtility.IsNullOrEmpty(data))
                throw new ArgumentException("Data must not be empty or all zero.", nameof(data));

            return HMACSHA512.HashData(key, data, result);
        }
        catch (Exception ex)
        {
            HkdfDiagnostics.RecordException(activity, ex);
            throw;
        }
    }
}
