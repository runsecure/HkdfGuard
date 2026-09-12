using Amazon.SecretsManager;
using Amazon.SecretsManager.Model;
using HkdfGuard.Abstractions;

namespace HkdfGuard.Cache.AwsSecretsManager;

/// <summary>
/// A ProtectedCacheBase pulled through from AWS Secrets Manager via the official AWS SDK.
/// Secrets are fetched as plaintext (Secrets Manager is trusted for confidentiality/access
/// control on its own) on a cache miss, then immediately encrypted into Cache via
/// dataProtectionKey, so nothing here ever holds Secrets Manager plaintext beyond the duration
/// of a single TryPopulate call. dataProtectionKey is expected to be an ephemeral key already
/// registered on a KeyRing (e.g. via KeyRingBuilder.AddEphemeralKey/
/// HkdfGuardOptions.EphemeralKeys) rather than one this class builds itself - its lifetime,
/// rotation, and sharing across caches stay a property of that KeyRing.
///
/// name is the secret's ARN or friendly name, passed straight through as GetSecretValueRequest.
/// SecretId. Only string secrets (SecretString) are supported - a secret stored as SecretBinary
/// throws NotSupportedException, since this library's cache values are text.
///
/// IAmazonSecretsManager has no synchronous API (the AWS SDK for .NET is async-only for this
/// service), while ProtectedCacheBase's contract is synchronous throughout this library, so
/// TryPopulate blocks on the async call via GetAwaiter().GetResult(). This is safe in a console
/// app or ASP.NET Core (Core 3+ has no capturing SynchronizationContext to deadlock against) but
/// does tie up a thread pool thread for the duration of the call, unlike
/// VaultProtectedCache/AzureKeyVaultProtectedCache, whose underlying clients expose a genuine
/// synchronous call path.
/// </summary>
public sealed class AwsSecretsManagerProtectedCache(IAmazonSecretsManager secretsManagerClient, IDataProtectionKey dataProtectionKey)
    : ProtectedCacheBase(dataProtectionKey)
{
    /// <inheritdoc/>
    protected override bool TryPopulate(string name)
    {
        using var activity = AwsSecretsManagerDiagnostics.ActivitySource.StartActivity("AwsSecretsManagerProtectedCache.TryPopulate");
        if (AwsSecretsManagerDiagnostics.EnableSensitiveLogging)
            AwsSecretsManagerDiagnostics.LogSensitiveOperation(activity, "AwsSecretsManagerProtectedCache.TryPopulate", ("name", name));

        try
        {
            var response = secretsManagerClient
                .GetSecretValueAsync(new GetSecretValueRequest { SecretId = name })
                .GetAwaiter()
                .GetResult();

            if (response.SecretString is null)
            {
                throw new NotSupportedException(
                    $"Secret '{name}' has no SecretString value - binary secrets (SecretBinary) are not supported.");
            }

            // response.SecretString is an immutable string owned by the AWS SDK, so it can't be
            // zeroed itself - copy it into a caller-owned Span<char> that EncryptChars can zero
            // once it's done encrypting.
            Span<char> secretChars = stackalloc char[response.SecretString.Length];
            response.SecretString.AsSpan().CopyTo(secretChars);
            Cache[name] = EncryptChars(secretChars);
            return true;
        }
        catch (ResourceNotFoundException)
        {
            return false;
        }
        catch (Exception ex)
        {
            AwsSecretsManagerDiagnostics.RecordException(activity, ex);
            throw;
        }
    }
}
