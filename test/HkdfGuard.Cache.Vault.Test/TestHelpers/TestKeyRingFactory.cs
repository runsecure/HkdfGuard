using HkdfGuard.Abstractions;
using HkdfGuard.Cache.Vault;
using HkdfGuard.Core.Cryptography;
using HkdfGuard.DataProtectionKey.FormatProvider;
using HkdfGuard.DataProtectionKey.KeyTracking;

namespace HkdfGuard.Cache.Vault.Test.TestHelpers;

/// <summary>
/// Builds a real KeyRing with a single ephemeral key registered (via KeyRingBuilder.
/// AddEphemeralKey, the intended real-world pattern), backed by an in-memory IKeyInputStorage so
/// tests never touch real OS-native secure storage.
/// </summary>
internal static class TestKeyRingFactory
{
    public const string ServiceName = "vault-cache-test-svc";

    public static KeyRing Create(IKeyInputStorage? storage = null)
        => new KeyRingBuilder()
            .WithCryptoRecipe(new CryptoRecipeBuilder()
                .WithServiceName(ServiceName)
                .WithKeyDerivation(new Pbkdf2KeyDerivationFunction(storage ?? new InMemoryKeyInputStorage()))
                .WithCipher(new AesGcmCipher())
                .WithHash(new HmacSha256Hash()))
            .WithKeyWrapperFactory(new HkdfKeyWrapperFactory())
            .WithKeyProtectorFactory(new KeyProtectorFactory())
            .AddEphemeralKey(version: 1, materialIdentifier: 1, iterations: 1)
            .Build();

    /// <summary>
    /// Protects plaintext via an IDataProtector bound to keyRing and
    /// VaultProtectedCache.ProtectorPurpose - mirrors how a real caller would produce the
    /// encrypted, formatted credentials VaultTokenAuthenticator/VaultUserPassAuthenticator now
    /// expect.
    /// </summary>
    public static string Encrypt(KeyRing keyRing, string plaintext)
        => keyRing.CreateProtector(VaultProtectedCache.ProtectorPurpose).Encrypt(plaintext.AsSpan());

    /// <summary>
    /// Reveals a formatted value back to plaintext, for asserting on what an authenticator
    /// actually protected.
    /// </summary>
    public static string Decrypt(KeyRing keyRing, string encrypted)
    {
        var protector = keyRing.CreateProtector(VaultProtectedCache.ProtectorPurpose);
        Span<char> result = new char[protector.GetMaxDecryptedLength(encrypted)];
        var written = protector.Decrypt(encrypted, result);
        return new string(result[..written]);
    }
}
