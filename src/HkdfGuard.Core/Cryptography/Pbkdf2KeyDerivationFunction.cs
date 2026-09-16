using System.Security.Cryptography;
using System.Text.Json.Serialization;
using HkdfGuard.Core.Diagnostics;
using HkdfGuard.Core.Utilities;
using HkdfGuard.Abstractions;

namespace HkdfGuard.Core.Cryptography;

public class Pbkdf2KeyDerivationFunction(IKeyInputStorage storage) : IKeyDerivationFunction
{
    /// <inheritdoc/>
    public int Derive(ReadOnlySpan<byte> uniqueBytes, ReadOnlySpan<byte> salt, int materialIdentifier, int iterations,
        string serviceName, scoped Span<byte> result)
    {
        using var activity = HkdfDiagnostics.ActivitySource.StartActivity("Pbkdf2KeyDerivationFunction.Derive");
        if (HkdfDiagnostics.EnableSensitiveLogging)
            HkdfDiagnostics.LogSensitiveOperation(activity, "Pbkdf2KeyDerivationFunction.Derive",
                ("serviceName", serviceName), ("materialIdentifier", materialIdentifier), ("iterations", iterations));

        Span<byte> keyMaterial = stackalloc byte[32];
        Span<byte> saltBytes = stackalloc byte[uniqueBytes.Length + salt.Length];
        try
        {
            if (ArrayUtility.IsNullOrEmpty(uniqueBytes))
                throw new ArgumentException("Unique bytes must not be empty or all zero.", nameof(uniqueBytes));

            uniqueBytes.CopyTo(saltBytes.Slice(0, uniqueBytes.Length));
            salt.CopyTo(saltBytes.Slice(uniqueBytes.Length, salt.Length));
            var index = $"{serviceName}.{materialIdentifier}";
            storage.CreateOrGet(index, keyMaterial);
            return DeriveCore(keyMaterial, saltBytes, iterations, result);
        }
        catch (Exception ex)
        {
            HkdfDiagnostics.RecordException(activity, ex);
            throw;
        }
        finally
        {
            ArrayUtility.ZeroMemory(keyMaterial);
            ArrayUtility.ZeroMemory(saltBytes);
        }
    }

    //The actual derivation requires a static set of keyMaterial during the 
    private int DeriveCore(ReadOnlySpan<byte> keyMaterial, ReadOnlySpan<byte> salt, 
        int iterations, scoped Span<byte> result)
    {
        Rfc2898DeriveBytes.Pbkdf2(keyMaterial, salt, result, iterations, HashAlgorithmName.SHA512);
        return result.Length;
    }
}