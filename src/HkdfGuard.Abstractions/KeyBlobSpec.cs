namespace HkdfGuard.Abstractions;

/// <summary>
/// Describes the byte length of each field in a serialized key blob, allowing IKeyBlob
/// implementations to support layouts other than a fixed one. MaterialIdentifier and Iterations
/// are not part of this layout - they live on the IKeySpec used to create/load the blob instead,
/// and the blob's Signature covers them so a mismatch against the original is detected on load.
/// </summary>
public sealed class KeyBlobSpec(
    int saltLength,
    int encryptedKeySaltLength,
    int encryptedKeyValueLength,
    int signatureLength)
{
    public int SaltLength { get; } = saltLength;
    public int EncryptedKeySaltLength { get; } = encryptedKeySaltLength;
    public int EncryptedKeyValueLength { get; } = encryptedKeyValueLength;
    public int SignatureLength { get; } = signatureLength;

    public int TotalLength =>
        SaltLength + EncryptedKeySaltLength + EncryptedKeyValueLength + SignatureLength;
}
