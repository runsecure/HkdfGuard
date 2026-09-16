using System.Diagnostics;
using HkdfGuard.DataProtectionKey.Diagnostics;

namespace HkdfGuard.DataProtectionKey.Test;

public class DataProtectionDiagnosticsTests
{
    [Fact]
    public void EnableSensitiveLogging_SetThroughDataProtectionDiagnostics_ReflectsInHkdfDiagnostics()
    {
        var original = DataProtectionDiagnostics.EnableSensitiveLogging;
        try
        {
            DataProtectionDiagnostics.EnableSensitiveLogging = true;
            Assert.True(HkdfGuard.Core.Diagnostics.HkdfDiagnostics.EnableSensitiveLogging);

            DataProtectionDiagnostics.EnableSensitiveLogging = false;
            Assert.False(HkdfGuard.Core.Diagnostics.HkdfDiagnostics.EnableSensitiveLogging);
        }
        finally
        {
            DataProtectionDiagnostics.EnableSensitiveLogging = original;
        }
    }

    [Fact]
    public void RecordException_WithNullActivity_DoesNotThrow()
    {
        var exception = Record.Exception(() =>
            DataProtectionDiagnostics.RecordException(null, new InvalidOperationException("test")));

        Assert.Null(exception);
    }

    [Fact]
    public void RecordException_WithRealActivity_RecordsExceptionAndErrorStatus()
    {
        using var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == DataProtectionDiagnostics.SourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded
        };
        ActivitySource.AddActivityListener(listener);

        using var activity = DataProtectionDiagnostics.ActivitySource.StartActivity("Test.RecordException");
        DataProtectionDiagnostics.RecordException(activity, new InvalidOperationException("boom"));

        Assert.NotNull(activity);
        Assert.Equal(ActivityStatusCode.Error, activity!.Status);
        Assert.Contains(activity.Events, e => e.Name == "exception");
    }

    [Fact]
    public void LogSensitiveOperation_WithNullActivity_DoesNotThrow()
    {
        var exception = Record.Exception(() =>
            DataProtectionDiagnostics.LogSensitiveOperation(null, "op", ("key", "value")));

        Assert.Null(exception);
    }

    [Fact]
    public void LogSensitiveOperation_WhenDisabled_DoesNotAddEvent()
    {
        var original = DataProtectionDiagnostics.EnableSensitiveLogging;
        try
        {
            DataProtectionDiagnostics.EnableSensitiveLogging = false;

            using var listener = new ActivityListener
            {
                ShouldListenTo = source => source.Name == DataProtectionDiagnostics.SourceName,
                Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded
            };
            ActivitySource.AddActivityListener(listener);

            using var activity = DataProtectionDiagnostics.ActivitySource.StartActivity("Test.LogDisabled");
            DataProtectionDiagnostics.LogSensitiveOperation(activity, "op", ("key", "value"));

            Assert.NotNull(activity);
            Assert.DoesNotContain(activity!.Events, e => e.Name == "op");
        }
        finally
        {
            DataProtectionDiagnostics.EnableSensitiveLogging = original;
        }
    }

    [Fact]
    public void LogSensitiveOperation_WhenEnabled_AddsEventWithTags()
    {
        var original = DataProtectionDiagnostics.EnableSensitiveLogging;
        try
        {
            DataProtectionDiagnostics.EnableSensitiveLogging = true;

            using var listener = new ActivityListener
            {
                ShouldListenTo = source => source.Name == DataProtectionDiagnostics.SourceName,
                Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded
            };
            ActivitySource.AddActivityListener(listener);

            using var activity = DataProtectionDiagnostics.ActivitySource.StartActivity("Test.LogEnabled");
            DataProtectionDiagnostics.LogSensitiveOperation(activity, "op", ("key", "value"));

            Assert.NotNull(activity);
            var loggedEvent = Assert.Single(activity!.Events, e => e.Name == "op");
            Assert.Contains(loggedEvent.Tags, t => t.Key == "key" && Equals(t.Value, "value"));
        }
        finally
        {
            DataProtectionDiagnostics.EnableSensitiveLogging = original;
        }
    }
}
