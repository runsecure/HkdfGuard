using System.Diagnostics;
using System.Text;
using System.Text.Json;
using HkdfGuard.DataProtectionKey.KeyTracking;

namespace HkdfGuard.Cache.Vault;

/// <summary>
/// Shared POST-a-login-request-and-extract-the-token logic for IVaultAuthenticator
/// implementations that need a real login call (VaultUserPassAuthenticator,
/// VaultTlsCertificateAuthenticator). The response is walked with a Utf8JsonReader rather than
/// JsonDocument specifically so the token can be converted directly from its raw UTF8 bytes into
/// a stackalloc'd char buffer whenever possible - never landing in a string or on the heap -
/// falling back to GetString only for the (essentially never true for a Vault token) escaped
/// case, since Utf8JsonReader has no public byte-span unescape API. The token is protected (via
/// an IDataProtector bound to keyRing and VaultProtectedCache.ProtectorPurpose) at the exact
/// point it's extracted, so the plaintext token never leaves ExtractClientToken at all - not
/// even as this method's own return value.
/// </summary>
internal static class VaultLoginClient
{
    public static string Login(HttpClient httpClient, string loginPath, HttpContent? content, string activityName, KeyRing keyRing)
    {
        using var activity = VaultDiagnostics.ActivitySource.StartActivity(activityName);

        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, loginPath) { Content = content };
            using var response = httpClient.Send(request);
            response.EnsureSuccessStatusCode();

            using var responseStream = response.Content.ReadAsStream();
            using var buffer = new MemoryStream();
            responseStream.CopyTo(buffer);

            return ExtractClientToken(buffer.ToArray(), loginPath, keyRing);
        }
        catch (Exception ex)
        {
            VaultDiagnostics.RecordException(activity, ex);
            throw;
        }
    }

    private static string ExtractClientToken(ReadOnlySpan<byte> json, string loginPath, KeyRing keyRing)
    {
        var reader = new Utf8JsonReader(json);

        while (reader.Read())
        {
            if (reader.TokenType != JsonTokenType.PropertyName || !reader.ValueTextEquals("auth"u8))
                continue;

            reader.Read();
            // Read() returning false here is unreachable: over a complete, well-formed buffer,
            // Utf8JsonReader only exhausts input after validly closing every open object/array
            // (which happens via the EndObject check below), and malformed/truncated input
            // throws JsonReaderException from Read() itself rather than returning false.
            while (reader.Read() && reader.TokenType != JsonTokenType.EndObject)
            {
                if (reader.TokenType != JsonTokenType.PropertyName || !reader.ValueTextEquals("client_token"u8))
                    continue;

                reader.Read();
                if (reader.TokenType != JsonTokenType.String)
                {
                    throw new InvalidOperationException(
                        $"Vault login response from '{loginPath}' had a non-string auth.client_token.");
                }

                var protector = keyRing.CreateProtector(VaultProtectedCache.ProtectorPurpose);

                // Prefer converting the raw UTF8 bytes directly off the reader into a
                // stackalloc'd char buffer - only fall back to GetString (which allocates a
                // string we can never clear) when the value is escaped, since Utf8JsonReader has
                // no public byte-span unescape API.
                if (!reader.ValueIsEscaped)
                {
                    // UTF8 byte count is always >= the decoded char count, so it's a safe buffer size.
                    Span<char> tokenChars = stackalloc char[reader.ValueSpan.Length];
                    try
                    {
                        var charsWritten = Encoding.UTF8.GetChars(reader.ValueSpan, tokenChars);
                        return protector.Encrypt(tokenChars[..charsWritten]);
                    }
                    finally
                    {
                        tokenChars.Clear();
                    }
                }

                return protector.Encrypt(reader.GetString());
            }
        }

        throw new InvalidOperationException($"Vault login response from '{loginPath}' did not include auth.client_token.");
    }
}
