using System.Security.Cryptography;
using HkdfGuard.Abstractions;
using HkdfGuard.Core.Primitives;

namespace HkdfGuard.Core.Test;

public class FlexibleKeyBlobTests
{
    private static readonly KeyBlobSpec Spec = new(
        saltLength: 64, encryptedKeySaltLength: 32, encryptedKeyValueLength: 60, signatureLength: 32);

    [Fact]
    public void Spec_ReturnsTheSpecItWasConstructedWith()
    {
        var blob = new FlexibleKeyBlob(Spec);

        Assert.Same(Spec, blob.Spec);
    }

    [Fact]
    public void SetThenFields_RoundTrip()
    {
        var salt = RandomNumberGenerator.GetBytes(Spec.SaltLength);
        var encryptedKeySalt = RandomNumberGenerator.GetBytes(Spec.EncryptedKeySaltLength);
        var encryptedKeyValue = RandomNumberGenerator.GetBytes(Spec.EncryptedKeyValueLength);
        var signature = RandomNumberGenerator.GetBytes(Spec.SignatureLength);

        var blob = new FlexibleKeyBlob(Spec, salt, encryptedKeySalt, encryptedKeyValue, signature);

        Assert.True(blob.Salt.SequenceEqual(salt));
        Assert.True(blob.EncryptedKeySalt.SequenceEqual(encryptedKeySalt));
        Assert.True(blob.EncryptedKeyValue.SequenceEqual(encryptedKeyValue));
        Assert.True(blob.Signature.SequenceEqual(signature));
    }

    [Fact]
    public void Set_WithWrongSaltLength_Throws()
    {
        var blob = new FlexibleKeyBlob(Spec);

        Assert.Throws<ArgumentException>(() => blob.Set(
            new byte[Spec.SaltLength - 1],
            new byte[Spec.EncryptedKeySaltLength],
            new byte[Spec.EncryptedKeyValueLength],
            new byte[Spec.SignatureLength]));
    }

    [Fact]
    public void Set_WithWrongEncryptedKeySaltLength_Throws()
    {
        var blob = new FlexibleKeyBlob(Spec);

        Assert.Throws<ArgumentException>(() => blob.Set(
            new byte[Spec.SaltLength],
            new byte[Spec.EncryptedKeySaltLength - 1],
            new byte[Spec.EncryptedKeyValueLength],
            new byte[Spec.SignatureLength]));
    }

    [Fact]
    public void Set_WithWrongEncryptedKeyValueLength_Throws()
    {
        var blob = new FlexibleKeyBlob(Spec);

        Assert.Throws<ArgumentException>(() => blob.Set(
            new byte[Spec.SaltLength],
            new byte[Spec.EncryptedKeySaltLength],
            new byte[Spec.EncryptedKeyValueLength - 1],
            new byte[Spec.SignatureLength]));
    }

    [Fact]
    public void Set_WithWrongSignatureLength_Throws()
    {
        var blob = new FlexibleKeyBlob(Spec);

        Assert.Throws<ArgumentException>(() => blob.Set(
            new byte[Spec.SaltLength],
            new byte[Spec.EncryptedKeySaltLength],
            new byte[Spec.EncryptedKeyValueLength],
            new byte[Spec.SignatureLength - 1]));
    }

    [Fact]
    public void TryLoad_WithCorrectLength_ReturnsTrue()
    {
        var blob = new FlexibleKeyBlob(Spec);

        Assert.True(blob.TryLoad(new byte[Spec.TotalLength]));
    }

    [Fact]
    public void TryLoad_WithWrongLength_ReturnsFalse()
    {
        var blob = new FlexibleKeyBlob(Spec);

        Assert.False(blob.TryLoad(new byte[Spec.TotalLength - 1]));
    }

    [Fact]
    public void SaveThenTryLoad_RoundTrips()
    {
        var salt = RandomNumberGenerator.GetBytes(Spec.SaltLength);
        var encryptedKeySalt = RandomNumberGenerator.GetBytes(Spec.EncryptedKeySaltLength);
        var encryptedKeyValue = RandomNumberGenerator.GetBytes(Spec.EncryptedKeyValueLength);
        var signature = RandomNumberGenerator.GetBytes(Spec.SignatureLength);
        var original = new FlexibleKeyBlob(Spec, salt, encryptedKeySalt, encryptedKeyValue, signature);

        var savedBytes = new byte[Spec.TotalLength];
        var written = original.Save(savedBytes);

        var loaded = new FlexibleKeyBlob(Spec);
        Assert.True(loaded.TryLoad(savedBytes));

        Assert.Equal(Spec.TotalLength, written);
        Assert.True(loaded.Salt.SequenceEqual(salt));
        Assert.True(loaded.EncryptedKeySalt.SequenceEqual(encryptedKeySalt));
        Assert.True(loaded.EncryptedKeyValue.SequenceEqual(encryptedKeyValue));
        Assert.True(loaded.Signature.SequenceEqual(signature));
    }

    [Fact]
    public void Save_WithTooSmallDestination_Throws()
    {
        var blob = new FlexibleKeyBlob(Spec);

        Assert.Throws<ArgumentException>(() => blob.Save(new byte[Spec.TotalLength - 1]));
    }
}
