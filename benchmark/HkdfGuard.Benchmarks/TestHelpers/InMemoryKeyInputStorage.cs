using System.Security.Cryptography;
using HkdfGuard.Abstractions;

namespace HkdfGuard.Benchmarks.TestHelpers;

/// <summary>
/// Stands in for real OS-native secure storage so a benchmark can isolate the cost of the
/// algorithm it's actually measuring (PBKDF2, a cipher, the data-protection-key API) from the
/// cost of an OS keychain/credential-store/keyring round trip - that cost has its own dedicated
/// benchmark (see KeyInputStorageBenchmarks).
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
