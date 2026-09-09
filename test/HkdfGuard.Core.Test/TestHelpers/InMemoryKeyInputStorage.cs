using System.Security.Cryptography;
using HkdfGuard.Abstractions;

namespace HkdfGuard.Core.Test.TestHelpers;

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
