using Google.Cloud.SecretManager.V1;
using Grpc.Core;
using HkdfGuard.Abstractions;

namespace HkdfGuard.Cache.GoogleSecretManager;

/// <summary>
/// A ProtectedCacheBase pulled through from Google Cloud Secret Manager via the official Google
/// client library. Secrets are fetched as plaintext (Secret Manager is trusted for
/// confidentiality/access control on its own) on a cache miss, then immediately encrypted into
/// Cache via dataProtectionKey, so nothing here ever holds Secret Manager plaintext beyond the
/// duration of a single TryPopulate call. dataProtectionKey is expected to be an ephemeral key
/// already registered on a KeyRing (e.g. via KeyRingBuilder.AddEphemeralKey/
/// HkdfGuardOptions.EphemeralKeys) rather than one this class builds itself - its lifetime,
/// rotation, and sharing across caches stay a property of that KeyRing.
///
/// name is the full secret version resource name Secret Manager expects (e.g.
/// "projects/my-project/secrets/my-secret/versions/latest"), passed straight through to
/// AccessSecretVersion. Unlike AwsSecretsManagerProtectedCache, this runs on the client
/// library's genuine synchronous call path (SecretManagerServiceClient.AccessSecretVersion is a
/// real sync method, not a blocked-on async one), consistent with
/// VaultProtectedCache/AzureKeyVaultProtectedCache.
/// </summary>
public sealed class GoogleSecretManagerProtectedCache(SecretManagerServiceClient secretManagerClient, IDataProtectionKey dataProtectionKey)
    : ProtectedCacheBase(dataProtectionKey)
{
    /// <inheritdoc/>
    protected override bool TryPopulate(string name)
    {
        using var activity = GoogleSecretManagerDiagnostics.ActivitySource.StartActivity("GoogleSecretManagerProtectedCache.TryPopulate");
        if (GoogleSecretManagerDiagnostics.EnableSensitiveLogging)
            GoogleSecretManagerDiagnostics.LogSensitiveOperation(activity, "GoogleSecretManagerProtectedCache.TryPopulate", ("name", name));

        try
        {
            var response = secretManagerClient.AccessSecretVersion(name);
            Cache[name] = EncryptChars(response.Payload.Data.ToStringUtf8().AsSpan());
            return true;
        }
        catch (RpcException ex) when (ex.StatusCode == StatusCode.NotFound)
        {
            return false;
        }
        catch (Exception ex)
        {
            GoogleSecretManagerDiagnostics.RecordException(activity, ex);
            throw;
        }
    }
}
