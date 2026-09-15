using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using HkdfGuard.Core.Cryptography;

namespace HkdfGuard.Benchmarks;

/// <summary>
/// Benchmarks AesGcmCipher.Encrypt/Decrypt - the raw symmetric-cipher cost underlying every
/// higher-level operation in this library, isolated from key derivation and storage. Encrypt
/// zeroes its key and plaintext arguments as a side effect once it's done with them (defense
/// against leaving cleartext key material lingering in memory), so both are refreshed from a
/// pristine template before every invocation here - that copy is a cost a real caller supplying
/// its own reusable buffers would pay too; skipping it would only measure the first call
/// correctly and throw on every one after (Encrypt rejects an all-zero plaintext/key). PayloadSize
/// is parameterized across a small secret (64 bytes), a typical config blob (4 KiB), and a larger
/// payload (1 MiB) to show how per-call overhead versus per-byte throughput trade off.
/// </summary>
[MemoryDiagnoser]
public class AesGcmCipherBenchmarks
{
    private const int NonceSize = 12;
    private const int TagSize = 16;

    [Params(64, 4096, 1_048_576)]
    public int PayloadSize { get; set; }

    private AesGcmCipher _cipher = null!;
    private byte[] _keyTemplate = null!;
    private byte[] _plaintextTemplate = null!;
    private byte[] _keyScratch = null!;
    private byte[] _plaintextScratch = null!;
    private byte[] _encryptResult = null!;
    private byte[] _ciphertext = null!;
    private byte[] _decryptResult = null!;

    [GlobalSetup]
    public void GlobalSetup()
    {
        _cipher = new AesGcmCipher();
        _keyTemplate = RandomNumberGenerator.GetBytes(32);
        _plaintextTemplate = RandomNumberGenerator.GetBytes(PayloadSize);
        _keyScratch = new byte[32];
        _plaintextScratch = new byte[PayloadSize];
        _encryptResult = new byte[PayloadSize + NonceSize + TagSize];
        _decryptResult = new byte[PayloadSize];

        // Precompute one ciphertext to decrypt repeatedly - Decrypt only zeroes its key argument,
        // never its ciphertext, so this buffer is safe to reuse across every Decrypt invocation.
        var keyForCiphertext = (byte[])_keyTemplate.Clone();
        var plaintextForCiphertext = (byte[])_plaintextTemplate.Clone();
        _ciphertext = new byte[PayloadSize + NonceSize + TagSize];
        _cipher.Encrypt(keyForCiphertext, plaintextForCiphertext, _ciphertext);
    }

    [Benchmark]
    public int Encrypt()
    {
        _keyTemplate.CopyTo(_keyScratch, 0);
        _plaintextTemplate.CopyTo(_plaintextScratch, 0);
        return _cipher.Encrypt(_keyScratch, _plaintextScratch, _encryptResult);
    }

    [Benchmark]
    public int Decrypt()
    {
        _keyTemplate.CopyTo(_keyScratch, 0);
        return _cipher.Decrypt(_keyScratch, _ciphertext, _decryptResult);
    }
}
