namespace HkdfGuard.Abstractions;

/// <summary>
/// Read surface of a highly concurrent name -&gt; encrypted-value cache backed by a single
/// IDataProtectionKey. Names are compared case-insensitively (OrdinalIgnoreCase), matching
/// ConcurrentDictionary conventions. TryDecrypt reveals a stored value back into a caller-owned
/// buffer without throwing for a missing name. Nothing here ever holds plaintext beyond the
/// duration of a single TryDecrypt call - only the encrypted bytes are retained internally.
/// </summary>
public interface IProtectedReadOnlyCache
{
    /// <summary>
    /// Attempts to decrypt the value stored under name into result.
    /// </summary>
    /// <param name="name">The name the value was stored under</param>
    /// <param name="result">The span to receive the decrypted plaintext bytes</param>
    /// <param name="written">Number of bytes written to result, when successful</param>
    /// <returns>True if a value was stored under name and was successfully decrypted</returns>
    public bool TryDecrypt(string name, Span<byte> result, out int written);

    /// <summary>
    /// Attempts to decrypt the value stored under name into result as UTF8-decoded characters.
    /// </summary>
    /// <param name="name">The name the value was stored under</param>
    /// <param name="result">The span to receive the decrypted plaintext characters</param>
    /// <param name="written">Number of chars written to result, when successful</param>
    /// <returns>True if a value was stored under name and was successfully decrypted</returns>
    public bool TryDecrypt(string name, Span<char> result, out int written);

    /// <summary>
    /// Attempts to compute an upper bound on how many bytes or chars TryDecrypt will write for
    /// the value stored under name, so a result buffer can be sized without decrypting first.
    /// </summary>
    /// <param name="name">The name the value was stored under</param>
    /// <param name="maxLength">An upper bound on the decrypted length, when successful</param>
    /// <returns>True if a value is stored under name</returns>
    public bool TryGetMaxDecryptedLength(string name, out int maxLength);
}
