namespace HkdfGuard.Abstractions;

public interface IKeyBlob
{
    /// <summary>
    /// The KeySpec describing this blob's field layout, needed to size a Save destination buffer
    /// </summary>
    public KeyBlobSpec Spec { get; }

    public ReadOnlySpan<byte> Salt { get; }
    public ReadOnlySpan<byte> EncryptedKeySalt { get; }
    public ReadOnlySpan<byte> EncryptedKeyValue { get; }
    public ReadOnlySpan<byte> Signature { get; }

    /// <summary>
    /// Parses a serialized key blob according to this instance's KeySpec
    /// </summary>
    /// <param name="data">The serialized blob bytes</param>
    /// <returns>True if the data matched the configured KeySpec length and was loaded</returns>
    public bool TryLoad(ReadOnlySpan<byte> data);

    /// <summary>
    /// Serializes the currently held field values according to this instance's KeySpec
    /// </summary>
    /// <param name="destination">The span to receive the serialized blob</param>
    /// <returns>Number of bytes written to the destination</returns>
    public int Save(Span<byte> destination);
}
