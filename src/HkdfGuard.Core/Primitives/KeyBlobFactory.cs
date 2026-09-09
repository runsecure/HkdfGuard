using System.Buffers.Binary;
using System.Security.Cryptography;
using HkdfGuard.Abstractions;

namespace HkdfGuard.Core.Primitives;

/// <summary>
/// Builds a new IKeyBlob from a plaintext key by wrapping it via an IKeyProtector and signing
/// its header (Salt + the IKeySpec's MaterialIdentifier + Iterations), so the result is ready to
/// be written out with IKeyBlob.Save. MaterialIdentifier/Iterations are not themselves stored in
/// the blob - they come from the IKeySpec used to load it, and the signature only matches if
/// that spec's values are the same ones the blob was created with.
/// </summary>
public static class KeyBlobFactory
{
    // The signing-key derivation always uses a single iteration, independent of the spec's own
    // Iterations value (which governs the key-wrapping derivation instead).
    private const int SignatureIterations = 1;

    /// <summary>
    /// Wraps the plaintext key via the given IKeyProtector, signs the header, and returns a
    /// populated IKeyBlob ready to be saved.
    /// </summary>
    /// <param name="plaintextKey">The 32 byte plaintext key material to protect (consumed/zeroed by the wrapper)</param>
    /// <param name="wrapper">The IKeyProtector used to encrypt the plaintext key</param>
    /// <param name="keySpec">Supplies the key derivation, hash, material identifier, iterations, and service name used to sign the header</param>
    /// <param name="blobSpec">Describes the resulting blob's field layout</param>
    /// <param name="salt">The blob's salt - must be the same salt the wrapper itself uses to derive its wrapping key</param>
    /// <returns>A populated IKeyBlob, ready to be saved</returns>
    public static IKeyBlob Create(
        Span<byte> plaintextKey,
        IKeyProtector wrapper,
        IKeySpec keySpec,
        KeyBlobSpec blobSpec,
        ReadOnlySpan<byte> salt)
    {
        if (plaintextKey.Length != 32)
            throw new ArgumentException("Plaintext key must be 32 bytes.", nameof(plaintextKey));

        if (salt.Length != blobSpec.SaltLength)
            throw new ArgumentException($"Salt must be {blobSpec.SaltLength} bytes.", nameof(salt));

        // IKeyProtector.Encrypt writes its output as a single contiguous span; the KeyBlobSpec
        // decides where that output is split between EncryptedKeySalt and EncryptedKeyValue.
        var wrappedLength = blobSpec.EncryptedKeySaltLength + blobSpec.EncryptedKeyValueLength;
        var wrapped = new byte[wrappedLength];

        var written = wrapper.Encrypt(plaintextKey, wrapped);
        if (written != wrappedLength)
            throw new ArgumentException(
                $"IKeyProtector produced {written} bytes, but the KeyBlobSpec expects {wrappedLength} " +
                "(EncryptedKeySaltLength + EncryptedKeyValueLength).",
                nameof(blobSpec));

        var encryptedKeySalt = wrapped.AsSpan(0, blobSpec.EncryptedKeySaltLength);
        var encryptedKeyValue = wrapped.AsSpan(blobSpec.EncryptedKeySaltLength, blobSpec.EncryptedKeyValueLength);

        var signature = new byte[blobSpec.SignatureLength];
        if (blobSpec.SignatureLength > 0)
            Sign(salt, keySpec, signature);

        return new FlexibleKeyBlob(blobSpec, salt, encryptedKeySalt, encryptedKeyValue, signature);
    }

    /// <summary>
    /// Parses a serialized key blob and verifies its signature against the given IKeySpec,
    /// so the returned IKeyBlob only ever represents already-authenticated data - callers never
    /// need to re-check it, and it's safe to hold and reuse across classes in place of the raw
    /// bytes. Fails closed: any length mismatch or signature mismatch (wrong salt, wrong
    /// MaterialIdentifier/Iterations on the spec, wrong service name/host) returns false.
    /// </summary>
    /// <param name="data">The serialized blob bytes</param>
    /// <param name="keySpec">Supplies the key derivation, hash, material identifier, iterations, and service name the blob must have been signed with</param>
    /// <param name="blobSpec">Describes the blob's field layout</param>
    /// <param name="blob">The validated IKeyBlob, when successful</param>
    /// <returns>True if the blob was well-formed and its signature is valid</returns>
    public static bool TryLoad(
        ReadOnlySpan<byte> data,
        IKeySpec keySpec,
        KeyBlobSpec blobSpec,
        out IKeyBlob? blob)
    {
        var candidate = new FlexibleKeyBlob(blobSpec);
        if (!candidate.TryLoad(data))
        {
            blob = null;
            return false;
        }

        if (blobSpec.SignatureLength == 0)
        {
            blob = candidate;
            return true;
        }

        Span<byte> expectedSignature = stackalloc byte[blobSpec.SignatureLength];
        try
        {
            Sign(candidate.Salt, keySpec, expectedSignature);

            if (!CryptographicOperations.FixedTimeEquals(expectedSignature, candidate.Signature))
            {
                blob = null;
                return false;
            }

            blob = candidate;
            return true;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expectedSignature);
        }
    }

    // Signs Salt + MaterialIdentifier + Iterations using a signing key derived with a fixed
    // single iteration, so loading with a spec configured with different values fails to verify.
    private static void Sign(ReadOnlySpan<byte> salt, IKeySpec keySpec, Span<byte> result)
    {
        Span<byte> signingKey = stackalloc byte[32];
        try
        {
            keySpec.KeyDerivation.Derive(
                salt, salt, keySpec.MaterialIdentifier, SignatureIterations, keySpec.ServiceName, signingKey);

            // MaterialIdentifier/Iterations are now full ints, so each gets its own 4 bytes here
            // rather than being truncated to a single byte - truncating would let different
            // values alias to the same signed byte and defeat the mismatch check entirely.
            Span<byte> message = stackalloc byte[salt.Length + 8];
            salt.CopyTo(message);
            BinaryPrimitives.WriteInt32LittleEndian(message.Slice(salt.Length, 4), keySpec.MaterialIdentifier);
            BinaryPrimitives.WriteInt32LittleEndian(message.Slice(salt.Length + 4, 4), keySpec.Iterations);

            keySpec.Hash.ComputeHash(signingKey, message, result);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signingKey);
        }
    }
}
