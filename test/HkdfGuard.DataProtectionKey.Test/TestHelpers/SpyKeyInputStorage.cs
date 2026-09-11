using System.Security.Cryptography;
using HkdfGuard.Abstractions;

namespace HkdfGuard.DataProtectionKey.Test.TestHelpers;

/// <summary>
/// An IKeyInputStorage that records every index it's asked to resolve and how many times -
/// isolates tests asserting on when/whether key-derivation input was actually touched (e.g.
/// EphemeralDataProtectionKey's lazy first-use) from the real OS-native storage machinery.
/// </summary>
internal sealed class SpyKeyInputStorage : IKeyInputStorage
{
    private readonly Dictionary<string, byte[]> _store = new();

    public int CreateOrGetCallCount { get; private set; }
    public List<string> RequestedIndices { get; } = [];

    public int CreateOrGet(string index, Span<byte> material)
    {
        CreateOrGetCallCount++;
        RequestedIndices.Add(index);

        if (!_store.TryGetValue(index, out var existing))
        {
            existing = RandomNumberGenerator.GetBytes(material.Length);
            _store[index] = existing;
        }

        existing.CopyTo(material);
        return material.Length;
    }
}
