using System.Security.Cryptography;
using System.Text;
using HkdfGuard.Core.Primitives;

namespace HkdfGuard.Core.Test;

public class KeyDerivationSaltTests
{
    private static byte[] CreateSalt() => RandomNumberGenerator.GetBytes(32);

    [Fact]
    public void Constructor_SaltOnly_AsSpanReturnsSalt()
    {
        var salt = CreateSalt();

        var derivationSalt = new KeyDerivationSalt(salt);

        Assert.True(derivationSalt.AsSpan().SequenceEqual(salt));
    }

    [Fact]
    public void Constructor_SaltAndByteInfo_AsSpanReturnsSaltThenInfo()
    {
        var salt = CreateSalt();
        var info = "info"u8.ToArray();

        var derivationSalt = new KeyDerivationSalt(salt, info);

        Assert.True(derivationSalt.AsSpan().SequenceEqual([.. salt, .. info]));
    }

    [Fact]
    public void Constructor_SaltAndCharInfo_AsSpanReturnsSaltThenUtf8Info()
    {
        var salt = CreateSalt();
        const string info = "héllo";

        var derivationSalt = new KeyDerivationSalt(salt, info.AsSpan());

        Assert.True(derivationSalt.AsSpan().SequenceEqual([.. salt, .. Encoding.UTF8.GetBytes(info)]));
    }

    [Fact]
    public void Constructor_WithAllZeroSalt_Throws()
    {
        Assert.Throws<ArgumentException>(() => new KeyDerivationSalt(new byte[32]));
    }

    [Fact]
    public void Constructor_WithEmptySalt_Throws()
    {
        Assert.Throws<ArgumentException>(() => new KeyDerivationSalt(ReadOnlySpan<byte>.Empty));
    }

    [Fact]
    public void Constructor_WithSaltLengthNotMultipleOf32_Throws()
    {
        Assert.Throws<ArgumentException>(() => new KeyDerivationSalt(RandomNumberGenerator.GetBytes(31)));
    }

    [Fact]
    public void Constructor_SaltAndByteInfo_WithInvalidSalt_Throws()
    {
        Assert.Throws<ArgumentException>(() => new KeyDerivationSalt(new byte[32], "info"u8.ToArray()));
    }

    [Fact]
    public void Constructor_SaltAndCharInfo_WithInvalidSalt_Throws()
    {
        Assert.Throws<ArgumentException>(() => new KeyDerivationSalt(new byte[32], "info".AsSpan()));
    }
}
