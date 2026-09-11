using Azure;
using Azure.Security.KeyVault.Secrets;

namespace HkdfGuard.Cache.AzureKeyVault.Test.TestHelpers;

/// <summary>
/// A SecretClient test double (subclassing SecretClient's protected parameterless constructor,
/// the officially supported Azure SDK mocking approach) backed by an in-memory dictionary - lets
/// tests exercise AzureKeyVaultProtectedCache.TryPopulate's found/not-found/error paths without a
/// real Key Vault.
/// </summary>
internal sealed class FakeSecretClient(Dictionary<string, string> secrets) : SecretClient
{
    public int GetSecretCallCount { get; private set; }
    public Exception? ThrowOnGetSecret { get; set; }

    public override Response<KeyVaultSecret> GetSecret(string name, string? version = null, SecretContentType? outContentType = null, CancellationToken cancellationToken = default)
    {
        GetSecretCallCount++;

        if (ThrowOnGetSecret is not null)
            throw ThrowOnGetSecret;

        if (secrets.TryGetValue(name, out var value))
            return Response.FromValue(new KeyVaultSecret(name, value), new NullResponse());

        throw new RequestFailedException(404, $"Secret '{name}' not found.");
    }
}
