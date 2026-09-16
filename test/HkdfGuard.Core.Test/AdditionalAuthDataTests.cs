using System.Text;
using HkdfGuard.Core.Primitives;

namespace HkdfGuard.Core.Test;

public class AdditionalAuthDataTests
{
    [Fact]
    public void Empty_HasZeroLengthSpan()
    {
        Assert.True(AdditionalAuthData.Empty.AsSpan().IsEmpty);
    }

    [Fact]
    public void Constructor_Bytes_RoundTrips()
    {
        var bytes = "context"u8.ToArray();

        var aad = new AdditionalAuthData(bytes);

        Assert.True(aad.AsSpan().SequenceEqual(bytes));
    }

    [Fact]
    public void Constructor_Bytes_WithEmptySpan_ProducesEmptySpan()
    {
        var aad = new AdditionalAuthData(ReadOnlySpan<byte>.Empty);

        Assert.True(aad.AsSpan().IsEmpty);
    }

    [Fact]
    public void Constructor_Chars_RoundTripsAsUtf8()
    {
        const string text = "context";

        var aad = new AdditionalAuthData(text.AsSpan());

        Assert.True(aad.AsSpan().SequenceEqual(Encoding.UTF8.GetBytes(text)));
    }

    [Fact]
    public void Constructor_Chars_WithMultiByteUtf8_RoundTrips()
    {
        const string text = "héllo wörld 日本語";

        var aad = new AdditionalAuthData(text.AsSpan());

        Assert.True(aad.AsSpan().SequenceEqual(Encoding.UTF8.GetBytes(text)));
    }

    [Fact]
    public void Constructor_Chars_WithEmptySpan_ProducesEmptySpan()
    {
        var aad = new AdditionalAuthData(ReadOnlySpan<char>.Empty);

        Assert.True(aad.AsSpan().IsEmpty);
    }
}
