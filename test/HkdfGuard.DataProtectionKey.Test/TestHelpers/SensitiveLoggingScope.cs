using HkdfGuard.DataProtectionKey.Diagnostics;

namespace HkdfGuard.DataProtectionKey.Test.TestHelpers;

/// <summary>
/// Temporarily sets DataProtectionDiagnostics.EnableSensitiveLogging, restoring the original value
/// on Dispose - so a test can exercise a production method's "if enabled, log" branch without
/// leaking that shared static flag into other tests. Safe only because this assembly disables
/// test parallelization (see AssemblyInfo.cs) - EnableSensitiveLogging has no synchronization of
/// its own.
/// </summary>
internal readonly struct SensitiveLoggingScope : IDisposable
{
    private readonly bool _original;

    public SensitiveLoggingScope(bool enabled)
    {
        _original = DataProtectionDiagnostics.EnableSensitiveLogging;
        DataProtectionDiagnostics.EnableSensitiveLogging = enabled;
    }

    public void Dispose() => DataProtectionDiagnostics.EnableSensitiveLogging = _original;
}
