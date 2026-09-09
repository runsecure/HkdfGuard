namespace HkdfGuard.Abstractions;

public interface IKeyDerivationFunction
{
    /// <summary>
    /// Derives a key into the result span.
    /// </summary>
    /// <param name="uniqueBytes">Unique bytes for this specific key derivation</param>
    /// <param name="salt">The salt associated with the key material</param>
    /// <param name="materialIdentifier">Identifies which underlying key material to use</param>
    /// <param name="iterations">The iteration count to use for the derivation</param>
    /// <param name="serviceName">The assigned name or prefix for this service in keyStorage</param>
    /// <param name="result">The 32 byte span for the derived key</param>
    /// <returns>Number of bytes written to the derived key span</returns>
    public int Derive(ReadOnlySpan<byte> uniqueBytes, ReadOnlySpan<byte> salt, int materialIdentifier, int iterations,
        string serviceName, scoped Span<byte> result);
}
