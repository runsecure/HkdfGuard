using System.Net;

namespace HkdfGuard.Cache.Vault.Test.TestHelpers;

/// <summary>
/// An HttpMessageHandler test double that answers requests via a caller-supplied delegate, so
/// tests can exercise VaultProtectedCache/IVaultAuthenticator's real HTTP call sites without a
/// real Vault server. Overrides the synchronous Send (not just SendAsync) since
/// VaultProtectedCache/its authenticators call HttpClient.Send.
/// </summary>
internal sealed class FakeVaultHandler : HttpMessageHandler
{
    public List<HttpRequestMessage> Requests { get; } = [];
    public Func<HttpRequestMessage, HttpResponseMessage>? OnSend { get; set; }

    protected override HttpResponseMessage Send(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Requests.Add(request);
        return OnSend?.Invoke(request) ?? new HttpResponseMessage(HttpStatusCode.NotFound);
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        => Task.FromResult(Send(request, cancellationToken));
}
