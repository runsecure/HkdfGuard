using System.Security.Cryptography;
using HkdfGuard.Abstractions;
using HkdfGuard.DataProtectionKey.FormatProvider;
using HkdfGuard.DataProtectionKey.Test.TestHelpers;

namespace HkdfGuard.DataProtectionKey.Test;

public class DefaultFormatProviderTests
{
    private readonly DefaultFormatProvider _provider = new();

    [Fact]
    public void FormatParseGetMaxDecryptedLength_WithSensitiveLoggingEnabled_StillWorkCorrectly()
    {
        using var _ = new SensitiveLoggingScope(true);

        var value = new KeyTrackingValue { KeyVersion = 2, Value = "abc"u8.ToArray() };
        var formatted = _provider.Format(value);
        var parsed = _provider.Parse(formatted.AsSpan());
        var maxLength = _provider.GetMaxDecryptedLength(formatted.AsSpan());

        Assert.Equal(value.Value, parsed.Value);
        Assert.Equal(parsed.Value.Length, maxLength);
    }

    [Fact]
    public void FormatThenParse_RoundTrips()
    {
        var value = new KeyTrackingValue { KeyVersion = 7, Value = "hello"u8.ToArray() };

        var formatted = _provider.Format(value);
        Assert.StartsWith("enc::v7::", formatted);

        var parsed = _provider.Parse(formatted.AsSpan());
        Assert.Equal(7, parsed.KeyVersion);
        Assert.Equal(value.Value, parsed.Value);
    }

    [Fact]
    public void Format_WithEmptyValue_RoundTrips()
    {
        var value = new KeyTrackingValue { KeyVersion = 1, Value = [] };

        var formatted = _provider.Format(value);
        var parsed = _provider.Parse(formatted.AsSpan());

        Assert.Equal(1, parsed.KeyVersion);
        Assert.Empty(parsed.Value);
    }

    [Theory]
    [InlineData("")]
    [InlineData("no-delimiters-at-all")]
    [InlineData("enc::onlyonepart")]
    [InlineData("wrong::v1::AAAA")]
    [InlineData("enc::1::AAAA")]
    [InlineData("enc::vNotANumber::AAAA")]
    public void Parse_WithMalformedInput_ThrowsFormatException(string input)
        => Assert.Throws<FormatException>(() => _provider.Parse(input.AsSpan()));

    [Fact]
    public void Parse_WithInvalidBase64_ThrowsFormatException()
        => Assert.Throws<FormatException>(() => _provider.Parse("enc::v1::not-valid-base64!!!".AsSpan()));

    [Fact]
    public void GetMaxDecryptedLength_MatchesParsedValueLength()
    {
        var value = new KeyTrackingValue { KeyVersion = 3, Value = RandomNumberGenerator.GetBytes(40) };
        var formatted = _provider.Format(value);

        var maxLength = _provider.GetMaxDecryptedLength(formatted.AsSpan());
        var parsed = _provider.Parse(formatted.AsSpan());

        Assert.Equal(parsed.Value.Length, maxLength);
    }

    [Theory]
    [InlineData("")]
    [InlineData("enc::onlyonepart")]
    [InlineData("enc::1::AAAA")]
    public void GetMaxDecryptedLength_WithMalformedInput_ThrowsFormatException(string input)
        => Assert.Throws<FormatException>(() => _provider.GetMaxDecryptedLength(input.AsSpan()));

    [Fact]
    public void GetMaxDecryptedLength_WithInvalidBase64_ThrowsFormatException()
        => Assert.Throws<FormatException>(() => _provider.GetMaxDecryptedLength("enc::v1::not-valid-base64!!!".AsSpan()));
}
