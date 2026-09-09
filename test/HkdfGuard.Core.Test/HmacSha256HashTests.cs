using System.Security.Cryptography;
using HkdfGuard.Core.Cryptography;

namespace HkdfGuard.Core.Test;

public class HmacSha256HashTests
{
    [Fact]
    public void ComputeHash_MatchesFrameworkHmacSha256()
    {
        var hash = new HmacSha256Hash();
        var key = RandomNumberGenerator.GetBytes(32);
        var data = "the quick brown fox"u8.ToArray();
        var result = new byte[HmacSha256Hash.HashSize];

        var written = hash.ComputeHash(key, data, result);

        var expected = HMACSHA256.HashData(key, data);
        Assert.Equal(32, written);
        Assert.Equal(expected, result);
    }

    [Fact]
    public void ComputeHash_IsDeterministic()
    {
        var hash = new HmacSha256Hash();
        var key = RandomNumberGenerator.GetBytes(32);
        var first = new byte[32];
        var second = new byte[32];

        hash.ComputeHash(key, "payload"u8.ToArray(), first);
        hash.ComputeHash(key, "payload"u8.ToArray(), second);

        Assert.Equal(first, second);
    }

    [Fact]
    public void ComputeHash_DifferentKeys_ProduceDifferentHashes()
    {
        var hash = new HmacSha256Hash();
        var first = new byte[32];
        var second = new byte[32];

        hash.ComputeHash(RandomNumberGenerator.GetBytes(32), "payload"u8.ToArray(), first);
        hash.ComputeHash(RandomNumberGenerator.GetBytes(32), "payload"u8.ToArray(), second);

        Assert.NotEqual(first, second);
    }

    [Fact]
    public void ComputeHash_DifferentData_ProduceDifferentHashes()
    {
        var hash = new HmacSha256Hash();
        var key = RandomNumberGenerator.GetBytes(32);
        var first = new byte[32];
        var second = new byte[32];

        hash.ComputeHash(key, "payload-one"u8.ToArray(), first);
        hash.ComputeHash(key, "payload-two"u8.ToArray(), second);

        Assert.NotEqual(first, second);
    }
}
