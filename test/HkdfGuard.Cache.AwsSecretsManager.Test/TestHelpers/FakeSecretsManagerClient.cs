using Amazon;
using Amazon.Runtime;
using Amazon.SecretsManager;
using Amazon.SecretsManager.Model;

namespace HkdfGuard.Cache.AwsSecretsManager.Test.TestHelpers;

/// <summary>
/// An IAmazonSecretsManager test double (subclassing AmazonSecretsManagerClient - unlike
/// SecretClient, it has no protected parameterless constructor purely for mocking, so a real
/// RegionEndpoint has to be supplied just to satisfy its config validation - and overriding its
/// virtual GetSecretValueAsync) backed by an in-memory dictionary - lets tests exercise
/// AwsSecretsManagerProtectedCache.TryPopulate's found/not-found/error paths without a real AWS
/// account. No real AWS call is ever made - GetSecretValueAsync is fully overridden below.
/// </summary>
internal sealed class FakeSecretsManagerClient(Dictionary<string, string> secrets)
    : AmazonSecretsManagerClient(new AnonymousAWSCredentials(), RegionEndpoint.USEast1)
{
    public int GetSecretValueCallCount { get; private set; }
    public Exception? ThrowOnGetSecretValue { get; set; }

    /// <summary>
    /// When set, overrides the default dictionary-lookup response entirely - e.g. to simulate a
    /// secret with no SecretString (a binary-only secret).
    /// </summary>
    public Func<GetSecretValueRequest, GetSecretValueResponse>? OnGetSecretValue { get; set; }

    public override Task<GetSecretValueResponse> GetSecretValueAsync(
        GetSecretValueRequest request, CancellationToken cancellationToken = default)
    {
        GetSecretValueCallCount++;

        if (ThrowOnGetSecretValue is not null)
            throw ThrowOnGetSecretValue;

        if (OnGetSecretValue is not null)
            return Task.FromResult(OnGetSecretValue(request));

        if (secrets.TryGetValue(request.SecretId, out var value))
            return Task.FromResult(new GetSecretValueResponse { Name = request.SecretId, SecretString = value });

        throw new ResourceNotFoundException($"Secret '{request.SecretId}' not found.");
    }
}
