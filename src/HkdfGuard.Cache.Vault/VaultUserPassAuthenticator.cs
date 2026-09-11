using System.Buffers;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using HkdfGuard.DataProtectionKey.KeyTracking;

namespace HkdfGuard.Cache.Vault;

/// <summary>
/// IVaultAuthenticator using Vault's userpass auth method (POST auth/userpass/login/{username}).
/// Vault itself documents userpass as intended for development/testing rather than production
/// use - this exists to support that same integration/dev workflow, not as a production-grade
/// credential flow. encryptedUsername/encryptedPassword are assumed to already be formatted,
/// encrypted values (produced by an IDataProtector bound to
/// VaultProtectedCache.ProtectorPurpose, e.g. via the same KeyRing at setup time) rather than
/// held as plaintext; both are revealed only transiently, into stackalloc'd buffers, right
/// before building the login request, and cleared immediately after. The request body is built
/// with Utf8JsonWriter directly into a byte buffer rather than JsonSerializer - password is
/// written straight from its stackalloc'd char span into the JSON bytes, so it never passes
/// through an intermediate anonymous-object/string round trip.
/// </summary>
public sealed class VaultUserPassAuthenticator(string encryptedUsername, string encryptedPassword) : IVaultAuthenticator
{
    /// <inheritdoc/>
    public string GetToken(HttpClient httpClient, KeyRing keyRing)
    {
        var protector = keyRing.CreateProtector(VaultProtectedCache.ProtectorPurpose);

        Span<char> usernameChars = stackalloc char[protector.GetMaxDecryptedLength(encryptedUsername)];
        Span<char> passwordChars = stackalloc char[protector.GetMaxDecryptedLength(encryptedPassword)];
        try
        {
            var usernameWritten = protector.Decrypt(encryptedUsername, usernameChars);
            var passwordWritten = protector.Decrypt(encryptedPassword, passwordChars);
            var username = new string(usernameChars[..usernameWritten]);

            var bufferWriter = new ArrayBufferWriter<byte>();
            using (var writer = new Utf8JsonWriter(bufferWriter))
            {
                writer.WriteStartObject();
                writer.WriteString("password", passwordChars[..passwordWritten]);
                writer.WriteEndObject();
            }

            // ArrayBufferWriter<byte>.WrittenSpan is read-only by design (no mutable view to
            // zero), so bodyBytes below - a plain byte[] copy we fully control - is what's
            // actually cleared once the request is sent.
            var bodyBytes = bufferWriter.WrittenSpan.ToArray();
            try
            {
                using var content = new ByteArrayContent(bodyBytes);
                content.Headers.ContentType = new MediaTypeHeaderValue("application/json") { CharSet = "utf-8" };

                return VaultLoginClient.Login(
                    httpClient,
                    $"v1/auth/userpass/login/{Uri.EscapeDataString(username)}",
                    content,
                    "VaultUserPassAuthenticator.GetToken",
                    keyRing);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(bodyBytes);
            }
        }
        finally
        {
            usernameChars.Clear();
            passwordChars.Clear();
        }
    }
}
