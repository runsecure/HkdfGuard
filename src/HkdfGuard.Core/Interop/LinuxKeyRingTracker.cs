using System.Collections.Concurrent;

namespace HkdfGuard.Core.Interop;

internal static class LinuxKeyRingTracker
{
    private static ConcurrentDictionary<string, int> _keyRingIndexes = [];
    
    internal static bool TryGetValue(string index, out int value) => _keyRingIndexes.TryGetValue(index, out value);

    internal static void AddOrUpdate(string index, int value) => _keyRingIndexes[index] = value;
}