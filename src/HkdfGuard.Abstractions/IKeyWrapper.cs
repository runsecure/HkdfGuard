namespace HkdfGuard.Abstractions;

/// <summary>
/// Reveals the key held by an existing protected key blob. Standalone from IKeyProtector -
/// wrapping/protecting a key is a separate concern (see IKeyProtector), not this interface's.
/// Decrypt takes no ciphertext of its own - it always reveals this specific blob's own embedded
/// key (Salt + EncryptedKeySalt + EncryptedKeyValue), not arbitrary caller-supplied data.
/// </summary>
public interface IKeyWrapper
{
    /// <summary>
    /// Reveals this blob's protected key
    /// </summary>
    /// <param name="result">The decrypted key span</param>
    /// <returns>Number of bytes written to the result</returns>
    public int Decrypt(Span<byte> result);

    /// <summary>
    /// Reveals this blob's protected key
    /// </summary>
    /// <param name="aad">Additional Auth Data for decrypting the key</param>
    /// <param name="result">The decrypted key span</param>
    /// <returns>Number of bytes written to the result</returns>
    public int Decrypt(IAdditionalAuthData aad, Span<byte> result);
}
