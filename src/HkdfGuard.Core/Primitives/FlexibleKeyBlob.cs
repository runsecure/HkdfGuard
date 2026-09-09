using HkdfGuard.Abstractions;

namespace HkdfGuard.Core.Primitives;

/// <summary>
/// An IKeyBlob whose field layout is configured at construction via a KeyBlobSpec, rather
/// than fixed at compile time. Field order in the serialized bytes is: Salt, EncryptedKeySalt,
/// EncryptedKeyValue, Signature. MaterialIdentifier/Iterations are not stored here - they live
/// on the IKeySpec used to create/load the blob, and the Signature covers them instead.
/// </summary>
public sealed class FlexibleKeyBlob : IKeyBlob
{
    private readonly KeyBlobSpec _spec;
    private readonly byte[] _bytes;

    private readonly int _saltOffset;
    private readonly int _encryptedKeySaltOffset;
    private readonly int _encryptedKeyValueOffset;
    private readonly int _signatureOffset;

    public FlexibleKeyBlob(KeyBlobSpec spec)
    {
        _spec = spec;
        _bytes = new byte[spec.TotalLength];

        _saltOffset = 0;
        _encryptedKeySaltOffset = _saltOffset + spec.SaltLength;
        _encryptedKeyValueOffset = _encryptedKeySaltOffset + spec.EncryptedKeySaltLength;
        _signatureOffset = _encryptedKeyValueOffset + spec.EncryptedKeyValueLength;
    }

    public FlexibleKeyBlob(
        KeyBlobSpec spec,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> encryptedKeySalt,
        ReadOnlySpan<byte> encryptedKeyValue,
        ReadOnlySpan<byte> signature)
        : this(spec)
    {
        Set(salt, encryptedKeySalt, encryptedKeyValue, signature);
    }

    public KeyBlobSpec Spec => _spec;

    public ReadOnlySpan<byte> Salt => _bytes.AsSpan(_saltOffset, _spec.SaltLength);

    public ReadOnlySpan<byte> EncryptedKeySalt => _bytes.AsSpan(_encryptedKeySaltOffset, _spec.EncryptedKeySaltLength);

    public ReadOnlySpan<byte> EncryptedKeyValue => _bytes.AsSpan(_encryptedKeyValueOffset, _spec.EncryptedKeyValueLength);

    public ReadOnlySpan<byte> Signature => _bytes.AsSpan(_signatureOffset, _spec.SignatureLength);

    /// <summary>
    /// Sets the fields to be written by a subsequent call to Save
    /// </summary>
    public void Set(
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> encryptedKeySalt,
        ReadOnlySpan<byte> encryptedKeyValue,
        ReadOnlySpan<byte> signature)
    {
        if (salt.Length != _spec.SaltLength)
            throw new ArgumentException($"Salt must be {_spec.SaltLength} bytes.", nameof(salt));

        if (encryptedKeySalt.Length != _spec.EncryptedKeySaltLength)
            throw new ArgumentException($"Encrypted key salt must be {_spec.EncryptedKeySaltLength} bytes.", nameof(encryptedKeySalt));

        if (encryptedKeyValue.Length != _spec.EncryptedKeyValueLength)
            throw new ArgumentException($"Encrypted key value must be {_spec.EncryptedKeyValueLength} bytes.", nameof(encryptedKeyValue));

        if (signature.Length != _spec.SignatureLength)
            throw new ArgumentException($"Signature must be {_spec.SignatureLength} bytes.", nameof(signature));

        salt.CopyTo(_bytes.AsSpan(_saltOffset, _spec.SaltLength));
        encryptedKeySalt.CopyTo(_bytes.AsSpan(_encryptedKeySaltOffset, _spec.EncryptedKeySaltLength));
        encryptedKeyValue.CopyTo(_bytes.AsSpan(_encryptedKeyValueOffset, _spec.EncryptedKeyValueLength));
        signature.CopyTo(_bytes.AsSpan(_signatureOffset, _spec.SignatureLength));
    }

    public bool TryLoad(ReadOnlySpan<byte> data)
    {
        if (data.Length != _spec.TotalLength)
            return false;

        data.CopyTo(_bytes);
        return true;
    }

    public int Save(Span<byte> destination)
    {
        if (destination.Length < _spec.TotalLength)
            throw new ArgumentException("Destination buffer too small.", nameof(destination));

        _bytes.CopyTo(destination);
        return _spec.TotalLength;
    }
}
