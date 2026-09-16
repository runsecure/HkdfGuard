namespace HkdfGuard.Abstractions;

public interface IKeyProtector
{
    /// <summary>
    /// Protects an encryption key
    /// </summary>
    /// <param name="plaintext">The plain bytes to encrypt</param>
    /// <param name="result">The encrypted key</param>
    /// <returns>Number of bytes written to the result</returns>
    public int Encrypt(Span<byte> plaintext, Span<byte> result);

    /// <summary>
    /// Protects an encryption key
    /// </summary>
    /// <param name="plaintext">The plain bytes to encrypt</param>
    /// <param name="aad">Additional Auth Data for the encrypt operation</param>
    /// <param name="result">The encrypted key</param>
    /// <returns>Number of bytes written to the result</returns>
    public int Encrypt(Span<byte> plaintext, IAdditionalAuthData aad, Span<byte> result);
}
