namespace HkdfGuard.Abstractions;

public interface IAdditionalAuthData
{
    /// <summary>
    /// The Additional Authenticated Data as a byte span
    /// </summary>
    public ReadOnlySpan<byte> AsSpan();
}
