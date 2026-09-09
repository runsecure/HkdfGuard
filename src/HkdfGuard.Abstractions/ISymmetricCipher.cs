namespace HkdfGuard.Abstractions;

public interface ISymmetricCipher
{
    /// <summary>
    /// Encrypt the data
    /// </summary>
    /// <param name="key">The encryption key</param>
    /// <param name="plaintext">Plain data to encrypt</param>
    /// <param name="result">The span to hold the encrypted data</param>
    /// <returns>Number of bytes written to the encrypted span</returns>
    public int Encrypt(Span<byte> key, Span<byte> plaintext, Span<byte> result);

    /// <summary>
    /// Encrypt the data
    /// </summary>
    /// <param name="key">The encryption key</param>
    /// <param name="plaintext">Plain data to encrypt</param>
    /// <param name="aad">The Additional Auth Data for the encrypt operation</param>
    /// <param name="result">The span to hold the encrypted data</param>
    /// <returns>Number of bytes written to the encrypted span</returns>
    public int Encrypt(Span<byte> key, Span<byte> plaintext, IAdditionalAuthData aad, Span<byte> result);

    /// <summary>
    /// Decrypt the data
    /// </summary>
    /// <param name="key">The encryption key</param>
    /// <param name="ciphertext">The encrypted data to decrypt</param>
    /// <param name="result">The span to receive the decrypted data</param>
    /// <returns>The number of bytes written to the decrypted span</returns>
    public int Decrypt(Span<byte> key, ReadOnlySpan<byte> ciphertext, Span<byte> result);

    /// <summary>
    /// Decrypt the data
    /// </summary>
    /// <param name="key">The encryption key</param>
    /// <param name="ciphertext">The encrypted data to decrypt</param>
    /// <param name="aad">Additional Auth Data for the decrypt operation</param>
    /// <param name="result">The span to receive the decrypted data</param>
    /// <returns>The number of bytes written to the decrypted span</returns>
    public int Decrypt(Span<byte> key, ReadOnlySpan<byte> ciphertext, IAdditionalAuthData aad, Span<byte> result);
}
