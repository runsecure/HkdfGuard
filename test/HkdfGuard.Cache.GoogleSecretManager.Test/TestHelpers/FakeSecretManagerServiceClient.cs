using Google.Api.Gax.Grpc;
using Google.Cloud.SecretManager.V1;
using Google.Protobuf;
using Grpc.Core;

namespace HkdfGuard.Cache.GoogleSecretManager.Test.TestHelpers;

/// <summary>
/// A SecretManagerServiceClient test double (subclassing its protected parameterless
/// constructor - the officially supported approach for mocking this abstract client class - and
/// overriding its virtual, genuinely synchronous AccessSecretVersion) backed by an in-memory
/// dictionary - lets tests exercise GoogleSecretManagerProtectedCache.TryPopulate's
/// found/not-found/error paths without a real GCP project.
/// </summary>
internal sealed class FakeSecretManagerServiceClient(Dictionary<string, string> secrets) : SecretManagerServiceClient
{
    public int AccessSecretVersionCallCount { get; private set; }
    public Exception? ThrowOnAccessSecretVersion { get; set; }

    public override AccessSecretVersionResponse AccessSecretVersion(string name, CallSettings? callSettings = null)
    {
        AccessSecretVersionCallCount++;

        if (ThrowOnAccessSecretVersion is not null)
            throw ThrowOnAccessSecretVersion;

        if (secrets.TryGetValue(name, out var value))
        {
            return new AccessSecretVersionResponse
            {
                Name = name,
                Payload = new SecretPayload { Data = ByteString.CopyFromUtf8(value) }
            };
        }

        throw new RpcException(new Status(StatusCode.NotFound, $"Secret '{name}' not found."));
    }
}
