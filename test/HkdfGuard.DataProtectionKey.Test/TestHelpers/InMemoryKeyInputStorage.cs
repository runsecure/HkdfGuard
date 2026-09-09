using System.Security.Cryptography;
using HkdfGuard.Abstractions;

namespace HkdfGuard.DataProtectionKey.Test.TestHelpers;

/// <summary>
/// An in-memory IKeyInputStorage so tests never touch real OS-native secure storage (Keychain/
/// Credential Manager/systemd-creds) while still exercising the real Pbkdf2KeyDerivationFunction/
/// HkdfKeyWrapper/KeyBlobFactory pipeline end to end.
/// </summary>
internal sealed class InMemoryKeyInputStorage : IKeyInputStorage
{
    private readonly Dictionary<string, byte[]> _store = new();

    public int CreateOrGet(string index, Span<byte> material)
    {
        if (!_store.TryGetValue(index, out var existing))
        {
            existing = RandomNumberGenerator.GetBytes(material.Length);
            _store[index] = existing;
        }

        existing.CopyTo(material);
        return material.Length;
    }
}
