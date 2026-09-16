namespace HkdfGuard.Abstractions;

public interface IHash
{
    /// <summary>
    /// Computes a keyed hash (HMAC) over the provided data
    /// </summary>
    /// <param name="key">The signing key</param>
    /// <param name="data">Data to hash</param>
    /// <param name="result">The span to receive the computed hash</param>
    /// <returns>Number of bytes written to the result</returns>
    public int ComputeHash(ReadOnlySpan<byte> key, Span<byte> data, Span<byte> result);
}
