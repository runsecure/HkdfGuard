using Azure;
using Azure.Core;

namespace HkdfGuard.Cache.AzureKeyVault.Test.TestHelpers;

/// <summary>
/// A minimal Response stub for wrapping test values via Response.FromValue - none of its members
/// are ever actually read by AzureKeyVaultProtectedCache (it only reads Response&lt;T&gt;.Value),
/// so every member here is a harmless placeholder.
/// </summary>
internal sealed class NullResponse : Response
{
    public override int Status => 200;
    public override string ReasonPhrase => string.Empty;
    public override Stream? ContentStream { get; set; }
    public override string ClientRequestId { get; set; } = string.Empty;

    public override void Dispose()
    {
    }

    protected override bool ContainsHeader(string name) => false;

    protected override IEnumerable<HttpHeader> EnumerateHeaders() => [];

    protected override bool TryGetHeader(string name, out string value)
    {
        value = null!;
        return false;
    }

    protected override bool TryGetHeaderValues(string name, out IEnumerable<string> values)
    {
        values = null!;
        return false;
    }
}
