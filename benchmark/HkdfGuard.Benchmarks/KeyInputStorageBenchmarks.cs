using BenchmarkDotNet.Attributes;
using HkdfGuard.Abstractions;
using HkdfGuard.Core.Interop;

namespace HkdfGuard.Benchmarks;

/// <summary>
/// Benchmarks CreateOrGet against the real OS-native secure storage for whichever platform this
/// runs on (macOS Keychain, Windows Credential Manager, or the Linux kernel keyring via
/// systemd-creds) - selected at runtime by KeyInputStorageFactory, exactly as production code
/// does. Every key derivation in this library calls CreateOrGet fresh on every single operation
/// (see Pbkdf2KeyDerivationFunction.Derive) rather than caching the retrieved material, so this
/// is the floor latency every Encrypt/Decrypt pays before any actual cryptography runs.
/// GlobalSetup pre-creates the entry once so the benchmarked calls measure the steady-state
/// "retrieve existing material" path rather than one-time creation - that's the path every
/// operation after the very first hits in real usage.
/// </summary>
[MemoryDiagnoser]
public class KeyInputStorageBenchmarks
{
    private const string ServiceName = "HkdfGuard.Benchmarks";
    private const string Index = ServiceName + ".key-input-storage-benchmark";

    private IKeyInputStorage _storage = null!;
    private readonly byte[] _material = new byte[32];

    [GlobalSetup]
    public void GlobalSetup()
    {
        _storage = KeyInputStorageFactory.Create(ServiceName);
        _storage.CreateOrGet(Index, _material);
    }

    [Benchmark]
    public int CreateOrGet()
        => _storage.CreateOrGet(Index, _material);
}
