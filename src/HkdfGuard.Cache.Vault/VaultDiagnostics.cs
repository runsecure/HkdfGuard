using System.Diagnostics;
using HkdfGuard.Core.Diagnostics;

namespace HkdfGuard.Cache.Vault;

public static class VaultDiagnostics
{
    public const string SourceName = "HkdfGuard.Cache.Vault";

    public static readonly ActivitySource ActivitySource = new(SourceName);

    /// <summary>
    /// Shared with <see cref="HkdfDiagnostics.EnableSensitiveLogging"/> - one flag controls
    /// sensitive-operation debug logging across every HkdfGuard library.
    /// </summary>
    public static bool EnableSensitiveLogging
    {
        get => HkdfDiagnostics.EnableSensitiveLogging;
        set => HkdfDiagnostics.EnableSensitiveLogging = value;
    }

    public static void RecordException(Activity? activity, Exception exception)
        => HkdfDiagnostics.RecordException(activity, exception);

    public static void LogSensitiveOperation(Activity? activity, string operationName, params (string Key, object? Value)[] details)
        => HkdfDiagnostics.LogSensitiveOperation(activity, operationName, details);
}
