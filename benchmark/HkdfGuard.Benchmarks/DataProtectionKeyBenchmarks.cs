using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using HkdfGuard.Abstractions;
using HkdfGuard.Benchmarks.TestHelpers;
using HkdfGuard.Core.Cryptography;
using HkdfGuard.DataProtectionKey.Key;
using HkdfGuard.DataProtectionKey.KeyTracking;

namespace HkdfGuard.Benchmarks;

/// <summary>
/// Benchmarks the end-to-end data-protection-key API. Neither EphemeralDataProtectionKey nor the
/// IDataProtector built from a KeyRing caches its revealed key across calls - every Encrypt/Decrypt
/// re-derives it fresh via HkdfKeyWrapper (see KeyWrappedDataProtectionKey), so Iterations
/// dominates these numbers the same way it does Pbkdf2KeyDerivationBenchmarks; compare against
/// those to see how much of the cost here is the KDF versus everything else (the cipher, and for
/// IDataProtector, UTF8/base64 string formatting). An InMemoryKeyInputStorage stands in for real
/// OS storage (see KeyInputStorageBenchmarks for that separate cost). Plaintext is a fixed 64
/// bytes, representative of the small secrets (API keys, connection strings) this API protects -
/// not bulk data (see AesGcmCipherBenchmarks for cipher throughput at larger sizes).
/// </summary>
[MemoryDiagnoser]
public class DataProtectionKeyBenchmarks
{
    private const string ServiceName = "HkdfGuard.Benchmarks";
    private const int PlaintextSize = 64;

    [Params(100_000, 600_000)]
    public int Iterations { get; set; }

    private EphemeralDataProtectionKey _dataProtectionKey = null!;
    private byte[] _plaintextTemplate = null!;
    private byte[] _plaintextScratch = null!;
    private byte[] _ciphertext = null!;
    private byte[] _decryptResult = null!;

    private IDataProtector _dataProtector = null!;
    private string _protectedString = null!;
    private char[] _decryptedChars = null!;

    private static ICryptoRecipeBuilder CreateRecipe()
        => new CryptoRecipeBuilder()
            .WithServiceName(ServiceName)
            .WithKeyDerivation(new Pbkdf2KeyDerivationFunction(new InMemoryKeyInputStorage()))
            .WithCipher(new AesGcmCipher())
            .WithHash(new HmacSha256Hash());

    [GlobalSetup]
    public void GlobalSetup()
    {
        var keySpec = CreateRecipe()
            .WithMaterialIdentifier(1)
            .WithIterations(Iterations)
            .Build();

        _dataProtectionKey = new EphemeralDataProtectionKey(
            keySpec, new HkdfKeyWrapperFactory(), new KeyProtectorFactory());

        _plaintextTemplate = RandomNumberGenerator.GetBytes(PlaintextSize);
        _plaintextScratch = new byte[PlaintextSize];
        _decryptResult = new byte[PlaintextSize];

        // Encrypt zeroes its plaintext argument as a side effect (inherited from AesGcmCipher via
        // KeyWrappedDataProtectionKey), so this warm-up call - which also triggers the key's lazy
        // first-use initialization - runs on its own scratch copy, and the ciphertext benchmarked
        // by Decrypt is produced from a separate one.
        _plaintextTemplate.CopyTo(_plaintextScratch, 0);
        _dataProtectionKey.Encrypt(_plaintextScratch);

        var ciphertextSource = (byte[])_plaintextTemplate.Clone();
        _ciphertext = _dataProtectionKey.Encrypt(ciphertextSource);

        var ring = new KeyRingBuilder()
            .WithCryptoRecipe(CreateRecipe())
            .WithKeyWrapperFactory(new HkdfKeyWrapperFactory())
            .WithKeyProtectorFactory(new KeyProtectorFactory())
            .AddEphemeralKey(version: 1, materialIdentifier: 1, iterations: Iterations)
            .Build();

        _dataProtector = ring.CreateProtector("HkdfGuard.Benchmarks.DataProtector");
        _protectedString = _dataProtector.Encrypt("benchmark plaintext value");
        _decryptedChars = new char[_dataProtector.GetMaxDecryptedLength(_protectedString)];
    }

    [Benchmark]
    public byte[] EphemeralKey_Encrypt()
    {
        _plaintextTemplate.CopyTo(_plaintextScratch, 0);
        return _dataProtectionKey.Encrypt(_plaintextScratch);
    }

    [Benchmark]
    public int EphemeralKey_Decrypt()
        => _dataProtectionKey.Decrypt(_ciphertext, _decryptResult);

    [Benchmark]
    public string DataProtector_Encrypt()
        => _dataProtector.Encrypt("benchmark plaintext value");

    [Benchmark]
    public int DataProtector_Decrypt()
        => _dataProtector.Decrypt(_protectedString, _decryptedChars);
}
