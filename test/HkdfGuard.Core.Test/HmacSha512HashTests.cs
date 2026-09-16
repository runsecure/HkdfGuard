using System.Security.Cryptography;
using HkdfGuard.Core.Cryptography;

namespace HkdfGuard.Core.Test;

public class HmacSha512HashTests
{
    [Fact]
    public void ComputeHash_MatchesFrameworkHmacSha512()
    {
        var hash = new HmacSha512Hash();
        var key = RandomNumberGenerator.GetBytes(32);
        var data = "the quick brown fox"u8.ToArray();
        var result = new byte[HmacSha512Hash.HashSize];

        var written = hash.ComputeHash(key, data, result);

        var expected = HMACSHA512.HashData(key, data);
        Assert.Equal(64, written);
        Assert.Equal(expected, result);
    }

    [Fact]
    public void ComputeHash_IsDeterministic()
    {
        var hash = new HmacSha512Hash();
        var key = RandomNumberGenerator.GetBytes(32);
        var first = new byte[HmacSha512Hash.HashSize];
        var second = new byte[HmacSha512Hash.HashSize];

        hash.ComputeHash(key, "payload"u8.ToArray(), first);
        hash.ComputeHash(key, "payload"u8.ToArray(), second);

        Assert.Equal(first, second);
    }

    [Fact]
    public void ComputeHash_DifferentKeys_ProduceDifferentHashes()
    {
        var hash = new HmacSha512Hash();
        var first = new byte[HmacSha512Hash.HashSize];
        var second = new byte[HmacSha512Hash.HashSize];

        hash.ComputeHash(RandomNumberGenerator.GetBytes(32), "payload"u8.ToArray(), first);
        hash.ComputeHash(RandomNumberGenerator.GetBytes(32), "payload"u8.ToArray(), second);

        Assert.NotEqual(first, second);
    }

    [Fact]
    public void ComputeHash_DifferentData_ProduceDifferentHashes()
    {
        var hash = new HmacSha512Hash();
        var key = RandomNumberGenerator.GetBytes(32);
        var first = new byte[HmacSha512Hash.HashSize];
        var second = new byte[HmacSha512Hash.HashSize];

        hash.ComputeHash(key, "payload-one"u8.ToArray(), first);
        hash.ComputeHash(key, "payload-two"u8.ToArray(), second);

        Assert.NotEqual(first, second);
    }

    [Fact]
    public void ComputeHash_WithAllZeroKey_RecordsExceptionAndThrows()
    {
        var hash = new HmacSha512Hash();
        var result = new byte[HmacSha512Hash.HashSize];

        Assert.Throws<ArgumentException>(() => hash.ComputeHash(new byte[32], "payload"u8.ToArray(), result));
    }

    [Fact]
    public void ComputeHash_WithAllZeroData_RecordsExceptionAndThrows()
    {
        var hash = new HmacSha512Hash();
        var key = RandomNumberGenerator.GetBytes(32);
        var result = new byte[HmacSha512Hash.HashSize];

        Assert.Throws<ArgumentException>(() => hash.ComputeHash(key, new byte[16], result));
    }
}
