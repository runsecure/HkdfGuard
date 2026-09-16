using System.Security.Cryptography;
using HkdfGuard.Abstractions;
using HkdfGuard.Core.Cryptography;
using HkdfGuard.DataProtectionKey.FormatProvider;
using HkdfGuard.DataProtectionKey.Key;
using HkdfGuard.DataProtectionKey.KeyTracking;
using HkdfGuard.EncryptedConfiguration.Test.TestHelpers;
using Microsoft.Extensions.Configuration;

namespace HkdfGuard.EncryptedConfiguration.Test;

public class ProtectedConfigurationRootTests
{
    private static KeyRing CreateKeyRing()
    {
        var ring = new KeyRing(new DefaultFormatProvider());
        var key = new KeyWrappedDataProtectionKey(new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)), new AesGcmCipher());
        ring.Add(1, key);
        return ring;
    }

    private static IConfigurationRoot CreateConfigurationRoot(KeyRing keyRing, params (string Key, string PlaintextValue)[] protectedValues)
    {
        var protector = keyRing.CreateProtector(ProtectedConfigurationRoot.ProtectorName);
        var values = new Dictionary<string, string?>();
        foreach (var (key, plaintext) in protectedValues)
            values[key] = protector.Encrypt(plaintext);

        return new ConfigurationBuilder().AddInMemoryCollection(values).Build();
    }

    private static ProtectedConfigurationRoot CreateSut(KeyRing keyRing, out IConfigurationRoot configurationRoot,
        params (string Key, string PlaintextValue)[] protectedValues)
    {
        configurationRoot = CreateConfigurationRoot(keyRing, protectedValues);
        return new ProtectedConfigurationRoot(configurationRoot, keyRing);
    }

    [Fact]
    public void Decrypt_Chars_WithKnownName_RoundTrips()
    {
        var keyRing = CreateKeyRing();
        var sut = CreateSut(keyRing, out _, ("ConnectionStrings:Db", "Server=db;Password=hunter2"));

        var result = new char[64];
        var written = sut.Decrypt("ConnectionStrings:Db", result);

        Assert.True(written > 0);
        Assert.Equal("Server=db;Password=hunter2", new string(result, 0, written));
    }

    [Fact]
    public void Decrypt_Bytes_WithKnownName_RoundTrips()
    {
        var keyRing = CreateKeyRing();
        var sut = CreateSut(keyRing, out _, ("Secrets:ApiKey", "top-secret-api-key"));

        var result = new byte[64];
        var written = sut.Decrypt("Secrets:ApiKey", result);

        Assert.True(written > 0);
        Assert.Equal("top-secret-api-key", System.Text.Encoding.UTF8.GetString(result, 0, written));
    }

    [Fact]
    public void Decrypt_Chars_HandlesMultiByteUtf8()
    {
        var keyRing = CreateKeyRing();
        const string plaintext = "héllo wörld 日本語";
        var sut = CreateSut(keyRing, out _, ("Secret", plaintext));

        var result = new char[plaintext.Length];
        var written = sut.Decrypt("Secret", result);

        Assert.True(written > 0);
        Assert.Equal(plaintext, new string(result, 0, written));
    }

    [Fact]
    public void Decrypt_Chars_WithUnknownName_ReturnsZero()
    {
        var keyRing = CreateKeyRing();
        var sut = CreateSut(keyRing, out _);

        var written = sut.Decrypt("missing", new char[16]);

        Assert.Equal(0, written);
    }

    [Fact]
    public void Decrypt_Bytes_WithUnknownName_ReturnsZero()
    {
        var keyRing = CreateKeyRing();
        var sut = CreateSut(keyRing, out _);

        var written = sut.Decrypt("missing", new byte[16]);

        Assert.Equal(0, written);
    }

    [Fact]
    public void TryGetMaxDecryptedLength_WithKnownName_ReturnsTrueAndSafeUpperBound()
    {
        var keyRing = CreateKeyRing();
        var sut = CreateSut(keyRing, out _, ("Secret", "some plaintext value"));

        var found = sut.TryGetMaxDecryptedLength("Secret", out var maxLength);
        Assert.True(found);

        var result = new byte[maxLength];
        var written = sut.Decrypt("Secret", result);
        Assert.True(maxLength >= written);
    }

    [Fact]
    public void TryGetMaxDecryptedLength_WithUnknownName_ReturnsFalse()
    {
        var keyRing = CreateKeyRing();
        var sut = CreateSut(keyRing, out _);

        var found = sut.TryGetMaxDecryptedLength("missing", out var maxLength);

        Assert.False(found);
        Assert.Equal(0, maxLength);
    }

    [Fact]
    public void Decrypt_Chars_WithMalformedValue_ThrowsFormatException()
    {
        var keyRing = CreateKeyRing();
        var configurationRoot = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Bad"] = "not-a-protected-value" })
            .Build();
        var sut = new ProtectedConfigurationRoot(configurationRoot, keyRing);

        Assert.Throws<FormatException>(() => sut.Decrypt("Bad", new char[16]));
    }

    [Fact]
    public void Decrypt_Bytes_WithMalformedValue_ThrowsFormatException()
    {
        var keyRing = CreateKeyRing();
        var configurationRoot = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Bad"] = "not-a-protected-value" })
            .Build();
        var sut = new ProtectedConfigurationRoot(configurationRoot, keyRing);

        Assert.Throws<FormatException>(() => sut.Decrypt("Bad", new byte[16]));
    }

    [Fact]
    public void Decrypt_WithSensitiveLoggingEnabled_StillRoundTrips()
    {
        var original = EncryptedConfigurationDiagnostics.EnableSensitiveLogging;
        try
        {
            EncryptedConfigurationDiagnostics.EnableSensitiveLogging = true;

            var keyRing = CreateKeyRing();
            var sut = CreateSut(keyRing, out _, ("Secret", "top secret"));

            var charResult = new char[32];
            var charsWritten = sut.Decrypt("Secret", charResult);
            Assert.True(charsWritten > 0);
            Assert.Equal("top secret", new string(charResult, 0, charsWritten));

            var byteResult = new byte[32];
            var bytesWritten = sut.Decrypt("Secret", byteResult);
            Assert.True(bytesWritten > 0);
            Assert.Equal("top secret", System.Text.Encoding.UTF8.GetString(byteResult, 0, bytesWritten));
        }
        finally
        {
            EncryptedConfigurationDiagnostics.EnableSensitiveLogging = original;
        }
    }

    [Fact]
    public void Indexer_DelegatesToUnderlyingConfigurationRoot()
    {
        var keyRing = CreateKeyRing();
        var sut = CreateSut(keyRing, out var configurationRoot, ("PlainKey", "value"));

        // The indexer reads the raw (still-protected) string, unlike Decrypt.
        Assert.Equal(configurationRoot["PlainKey"], sut["PlainKey"]);

        sut["NewKey"] = "new-value";
        Assert.Equal("new-value", configurationRoot["NewKey"]);
    }

    [Fact]
    public void Providers_DelegatesToUnderlyingConfigurationRoot()
    {
        var keyRing = CreateKeyRing();
        var sut = CreateSut(keyRing, out var configurationRoot);

        Assert.Same(configurationRoot.Providers, sut.Providers);
    }

    [Fact]
    public void GetSection_DelegatesToUnderlyingConfigurationRoot()
    {
        var keyRing = CreateKeyRing();
        var sut = CreateSut(keyRing, out var configurationRoot, ("Parent:Child", "value"));

        var section = sut.GetSection("Parent");

        Assert.Equal(configurationRoot.GetSection("Parent").Path, section.Path);
        Assert.Equal(configurationRoot.GetSection("Parent")["Child"], section["Child"]);
    }

    [Fact]
    public void GetChildren_DelegatesToUnderlyingConfigurationRoot()
    {
        var keyRing = CreateKeyRing();
        var sut = CreateSut(keyRing, out var configurationRoot, ("Parent:Child", "value"));

        var sutChildKeys = sut.GetChildren().Select(c => c.Key).ToList();
        var rootChildKeys = configurationRoot.GetChildren().Select(c => c.Key).ToList();

        Assert.Equal(rootChildKeys, sutChildKeys);
    }

    [Fact]
    public void GetReloadToken_DelegatesToUnderlyingConfigurationRoot()
    {
        var keyRing = CreateKeyRing();
        var sut = CreateSut(keyRing, out var configurationRoot);

        Assert.NotNull(sut.GetReloadToken());
        Assert.Same(configurationRoot.GetReloadToken(), sut.GetReloadToken());
    }

    [Fact]
    public void Reload_DelegatesToUnderlyingConfigurationRoot()
    {
        var keyRing = CreateKeyRing();
        var sut = CreateSut(keyRing, out _);

        var exception = Record.Exception(() => sut.Reload());

        Assert.Null(exception);
    }
}
