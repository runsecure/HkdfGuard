using System.Diagnostics;

namespace HkdfGuard.EncryptedConfiguration.Test;

public class EncryptedConfigurationDiagnosticsTests
{
    [Fact]
    public void EnableSensitiveLogging_SetThroughEncryptedConfigurationDiagnostics_ReflectsInHkdfDiagnostics()
    {
        var original = EncryptedConfigurationDiagnostics.EnableSensitiveLogging;
        try
        {
            EncryptedConfigurationDiagnostics.EnableSensitiveLogging = true;
            Assert.True(HkdfGuard.Core.Diagnostics.HkdfDiagnostics.EnableSensitiveLogging);

            EncryptedConfigurationDiagnostics.EnableSensitiveLogging = false;
            Assert.False(HkdfGuard.Core.Diagnostics.HkdfDiagnostics.EnableSensitiveLogging);
        }
        finally
        {
            EncryptedConfigurationDiagnostics.EnableSensitiveLogging = original;
        }
    }

    [Fact]
    public void RecordException_WithNullActivity_DoesNotThrow()
    {
        var exception = Record.Exception(() =>
            EncryptedConfigurationDiagnostics.RecordException(null, new InvalidOperationException("test")));

        Assert.Null(exception);
    }

    [Fact]
    public void RecordException_WithRealActivity_RecordsExceptionAndErrorStatus()
    {
        using var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == EncryptedConfigurationDiagnostics.SourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded
        };
        ActivitySource.AddActivityListener(listener);

        using var activity = EncryptedConfigurationDiagnostics.ActivitySource.StartActivity("Test.RecordException");
        EncryptedConfigurationDiagnostics.RecordException(activity, new InvalidOperationException("boom"));

        Assert.NotNull(activity);
        Assert.Equal(ActivityStatusCode.Error, activity!.Status);
        Assert.Contains(activity.Events, e => e.Name == "exception");
    }

    [Fact]
    public void LogSensitiveOperation_WithNullActivity_DoesNotThrow()
    {
        var exception = Record.Exception(() =>
            EncryptedConfigurationDiagnostics.LogSensitiveOperation(null, "op", ("key", "value")));

        Assert.Null(exception);
    }

    [Fact]
    public void LogSensitiveOperation_WhenDisabled_DoesNotAddEvent()
    {
        var original = EncryptedConfigurationDiagnostics.EnableSensitiveLogging;
        try
        {
            EncryptedConfigurationDiagnostics.EnableSensitiveLogging = false;

            using var listener = new ActivityListener
            {
                ShouldListenTo = source => source.Name == EncryptedConfigurationDiagnostics.SourceName,
                Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded
            };
            ActivitySource.AddActivityListener(listener);

            using var activity = EncryptedConfigurationDiagnostics.ActivitySource.StartActivity("Test.LogDisabled");
            EncryptedConfigurationDiagnostics.LogSensitiveOperation(activity, "op", ("key", "value"));

            Assert.NotNull(activity);
            Assert.DoesNotContain(activity!.Events, e => e.Name == "op");
        }
        finally
        {
            EncryptedConfigurationDiagnostics.EnableSensitiveLogging = original;
        }
    }

    [Fact]
    public void LogSensitiveOperation_WhenEnabled_AddsEventWithTags()
    {
        var original = EncryptedConfigurationDiagnostics.EnableSensitiveLogging;
        try
        {
            EncryptedConfigurationDiagnostics.EnableSensitiveLogging = true;

            using var listener = new ActivityListener
            {
                ShouldListenTo = source => source.Name == EncryptedConfigurationDiagnostics.SourceName,
                Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded
            };
            ActivitySource.AddActivityListener(listener);

            using var activity = EncryptedConfigurationDiagnostics.ActivitySource.StartActivity("Test.LogEnabled");
            EncryptedConfigurationDiagnostics.LogSensitiveOperation(activity, "op", ("key", "value"));

            Assert.NotNull(activity);
            var loggedEvent = Assert.Single(activity!.Events, e => e.Name == "op");
            Assert.Contains(loggedEvent.Tags, t => t.Key == "key" && Equals(t.Value, "value"));
        }
        finally
        {
            EncryptedConfigurationDiagnostics.EnableSensitiveLogging = original;
        }
    }
}
