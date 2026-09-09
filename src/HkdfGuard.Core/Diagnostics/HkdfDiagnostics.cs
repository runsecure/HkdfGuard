using System.Diagnostics;

namespace HkdfGuard.Core.Diagnostics;

public static class HkdfDiagnostics
{
    public const string SourceName = "HkdfGuard";

    public static readonly ActivitySource ActivitySource = new(SourceName);

    /// <summary>
    /// When enabled, sensitive operations emit additional debug telemetry (operation
    /// metadata such as buffer lengths and identifiers). Raw key, plaintext, and
    /// ciphertext bytes are never logged, regardless of this setting.
    /// </summary>
    public static bool EnableSensitiveLogging { get; set; }

    /// <summary>
    /// Records an exception on the current activity and marks it as errored
    /// </summary>
    public static void RecordException(Activity? activity, Exception exception)
    {
        activity?.AddException(exception);
        activity?.SetStatus(ActivityStatusCode.Error, exception.Message);
    }

    /// <summary>
    /// Emits a debug event describing a sensitive operation, when <see cref="EnableSensitiveLogging"/> is set.
    /// Only pass non-sensitive metadata (lengths, identifiers, timings) as details - never raw key,
    /// plaintext, or ciphertext bytes.
    /// </summary>
    public static void LogSensitiveOperation(Activity? activity, string operationName, params (string Key, object? Value)[] details)
    {
        if (!EnableSensitiveLogging || activity is null)
            return;

        var tags = new ActivityTagsCollection();
        foreach (var (key, value) in details)
            tags[key] = value;

        activity.AddEvent(new ActivityEvent(operationName, tags: tags));
    }
}
