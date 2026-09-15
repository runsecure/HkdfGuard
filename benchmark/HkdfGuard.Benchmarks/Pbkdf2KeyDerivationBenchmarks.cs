using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using HkdfGuard.Benchmarks.TestHelpers;
using HkdfGuard.Core.Cryptography;

namespace HkdfGuard.Benchmarks;

/// <summary>
/// Benchmarks Pbkdf2KeyDerivationFunction.Derive in isolation from a real OS storage round trip
/// (see KeyInputStorageBenchmarks for that cost) - an InMemoryKeyInputStorage stands in for the
/// real backend so only the PBKDF2-HMAC-SHA256 computation itself is measured. Iterations is
/// parameterized across two common floors: 100,000 (a widely used minimum) and 600,000 (OWASP's
/// current recommendation for PBKDF2-HMAC-SHA256).
/// </summary>
[MemoryDiagnoser]
public class Pbkdf2KeyDerivationBenchmarks
{
    private const string ServiceName = "HkdfGuard.Benchmarks";
    private const int MaterialIdentifier = 1;

    [Params(100_000, 600_000)]
    public int Iterations { get; set; }

    private Pbkdf2KeyDerivationFunction _kdf = null!;
    private byte[] _uniqueBytes = null!;
    private byte[] _salt = null!;
    private readonly byte[] _result = new byte[32];

    [GlobalSetup]
    public void GlobalSetup()
    {
        _kdf = new Pbkdf2KeyDerivationFunction(new InMemoryKeyInputStorage());
        _uniqueBytes = RandomNumberGenerator.GetBytes(32);
        _salt = RandomNumberGenerator.GetBytes(64);
    }

    [Benchmark]
    public int Derive()
        => _kdf.Derive(_uniqueBytes, _salt, MaterialIdentifier, Iterations, ServiceName, _result);
}
