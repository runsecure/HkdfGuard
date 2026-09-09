namespace HkdfGuard.Abstractions;

public interface IDataProtectionKey
{
    /// <summary>
    /// Key Wrapper for protecting an encryption key
    /// </summary>
    /// <param name="plaintext">The plain bytes to encrypt</param>
    /// <param name="result">The encrypted key</param>
    /// <returns>Number of bytes written to the result</returns>
    public int Encrypt(Span<byte> plaintext, Span<byte> result);

    /// <summary>
    /// Key Wrapper for protecting an encryption key
    /// </summary>
    /// <param name="plaintext">The plain bytes to encrypt</param>
    /// <param name="aad">Additional Auth Data for the encrypt operation</param>
    /// <param name="result">The encrypted key</param>
    /// <returns>Number of bytes written to the result</returns>
    public int Encrypt(Span<byte> plaintext, IAdditionalAuthData aad, Span<byte> result);

    /// <summary>
    /// Key Wrapper for revealing an encryption key
    /// </summary>
    /// <param name="ciphertext">The encrypted key</param>
    /// <param name="result">The decrypted key span</param>
    /// <returns>Number of bytes written to the result</returns>
    public int Decrypt(ReadOnlySpan<byte> ciphertext, Span<byte> result);

    /// <summary>
    /// Key Wrapper for revealing an encryption key
    /// </summary>
    /// <param name="ciphertext">The encrypted key</param>
    /// <param name="aad">Additional Auth Data for decrypting the key</param>
    /// <param name="result">The decrypted key span</param>
    /// <returns>Number of bytes written to the result</returns>
    public int Decrypt(ReadOnlySpan<byte> ciphertext, IAdditionalAuthData aad, Span<byte> result);
}
