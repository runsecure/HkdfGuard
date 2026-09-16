using System.Security.Cryptography;
using HkdfGuard.Abstractions;
using HkdfGuard.Core.Cryptography;
using HkdfGuard.Core.Primitives;
using HkdfGuard.Initializer.Test.TestHelpers;

namespace HkdfGuard.Initializer.Test;

/// <summary>
/// Exercises InitializerApp.Run - the hkdfguard-init CLI's argument-parsing and execution logic -
/// directly, capturing output/error through StringWriters instead of the real Console. Any test
/// that reaches actual key derivation supplies a createKeySpec override backed by an in-memory
/// IKeyInputStorage, so this suite never touches real OS-native secure storage (Keychain/
/// Credential Manager/systemd-creds); pure argument-validation tests that return before any
/// crypto runs leave it at the real default deliberately, to prove they never get that far.
/// </summary>
public class InitializerAppTests
{
    private static readonly KeyBlobSpec BlobSpec = new(
        saltLength: 64, encryptedKeySaltLength: 32, encryptedKeyValueLength: 60, signatureLength: 64);

    private static Func<string, int, int, IKeySpec> CreateKeySpecFactory(IKeyInputStorage storage)
        => (serviceName, materialIdentifier, iterations) => new CryptoRecipeBuilder()
            .WithServiceName(serviceName)
            .WithKeyDerivation(new Pbkdf2KeyDerivationFunction(storage))
            .WithCipher(new AesGcmCipher())
            .WithHash(new HmacSha512Hash())
            .WithMaterialIdentifier(materialIdentifier)
            .WithIterations(iterations)
            .Build();

    private static (int ExitCode, string Output, string Error) Run(
        string[] args, Func<string, int, int, IKeySpec>? createKeySpec = null)
    {
        var output = new StringWriter();
        var error = new StringWriter();
        var exitCode = InitializerApp.Run(args, output, error, createKeySpec);
        return (exitCode, output.ToString(), error.ToString());
    }

    // Mirrors the real Initializer flow: loads the blob InitializerApp wrote and reveals its
    // protected key, exercising the same TryLoad -> HkdfKeyWrapper.Decrypt path production code
    // (and callers like KeyRingBuilder) uses to consume what this tool produces.
    private static byte[] RevealProtectedKey(string path, IKeySpec keySpec)
    {
        var blobBytes = File.ReadAllBytes(path);
        Assert.True(KeyBlobFactory.TryLoad(blobBytes, keySpec, BlobSpec, out var blob));

        var wrapper = new HkdfKeyWrapperFactory().Create(keySpec, blob!);
        var revealed = new byte[32];
        wrapper.Decrypt(revealed);
        return revealed;
    }

    [Fact]
    public void Run_WithNoArgs_PrintsUsageAndFails()
    {
        var (exitCode, _, error) = Run([]);

        Assert.Equal(1, exitCode);
        Assert.Contains("Usage:", error);
    }

    [Fact]
    public void Run_WithUnrecognizedArgument_Fails()
    {
        using var tempDir = new TempDirectory();

        var (exitCode, _, error) = Run([tempDir.GetFilePath("k.key"), "--nonsense"]);

        Assert.Equal(1, exitCode);
        Assert.Contains("Unrecognized argument", error);
    }

    [Theory]
    [InlineData("--material-identifier")]
    [InlineData("--iterations")]
    public void Run_WithMissingValueForIntFlag_Fails(string flag)
    {
        using var tempDir = new TempDirectory();

        var (exitCode, _, error) = Run([tempDir.GetFilePath("k.key"), flag]);

        Assert.Equal(1, exitCode);
        Assert.Contains("requires a positive integer value", error);
    }

    [Fact]
    public void Run_WithZeroMaterialIdentifier_Fails()
    {
        using var tempDir = new TempDirectory();

        var (exitCode, _, error) = Run([tempDir.GetFilePath("k.key"), "--material-identifier", "0", "--iterations", "1"]);

        Assert.Equal(1, exitCode);
        Assert.Contains("--material-identifier requires a positive integer value", error);
    }

    [Fact]
    public void Run_WithServiceNameMissingValue_Fails()
    {
        using var tempDir = new TempDirectory();

        var (exitCode, _, error) = Run([tempDir.GetFilePath("k.key"), "--service-name"]);

        Assert.Equal(1, exitCode);
        Assert.Contains("--service-name requires a value", error);
    }

    [Fact]
    public void Run_WithDekMissingValue_Fails()
    {
        using var tempDir = new TempDirectory();

        var (exitCode, _, error) = Run([tempDir.GetFilePath("k.key"), "--dek"]);

        Assert.Equal(1, exitCode);
        Assert.Contains("--dek requires", error);
    }

    [Fact]
    public void Run_WithoutMaterialIdentifierOrIterations_Fails()
    {
        using var tempDir = new TempDirectory();

        var (exitCode, _, error) = Run([tempDir.GetFilePath("k.key")]);

        Assert.Equal(1, exitCode);
        Assert.Contains("--material-identifier and --iterations are required", error);
    }

    [Fact]
    public void Run_WithInvalidBase64Dek_Fails()
    {
        using var tempDir = new TempDirectory();

        var (exitCode, _, error) = Run(
            [tempDir.GetFilePath("k.key"), "--dek", "not-valid-base64???", "--material-identifier", "1", "--iterations", "1"]);

        Assert.Equal(1, exitCode);
        Assert.Contains("--dek must be a base64-encoded 32 byte value", error);
    }

    [Fact]
    public void Run_WithWrongLengthDek_Fails()
    {
        using var tempDir = new TempDirectory();
        var shortDek = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));

        var (exitCode, _, error) = Run(
            [tempDir.GetFilePath("k.key"), "--dek", shortDek, "--material-identifier", "1", "--iterations", "1"]);

        Assert.Equal(1, exitCode);
        Assert.Contains("--dek must be a base64-encoded 32 byte value", error);
    }

    [Fact]
    public void Run_WithMissingKeyFileAndNoDek_Fails()
    {
        using var tempDir = new TempDirectory();

        var (exitCode, _, error) = Run(
            [tempDir.GetFilePath("missing.key"), "--material-identifier", "1", "--iterations", "1"]);

        Assert.Equal(1, exitCode);
        Assert.Contains("Key file not found", error);
    }

    [Fact]
    public void Run_WithExistingFileOfUnexpectedLength_Fails()
    {
        using var tempDir = new TempDirectory();
        var path = tempDir.GetFilePath("weird.key");
        File.WriteAllBytes(path, new byte[10]);

        var (exitCode, _, error) = Run([path, "--material-identifier", "1", "--iterations", "1"]);

        Assert.Equal(1, exitCode);
        Assert.Contains("Unexpected key file length", error);
    }

    [Fact]
    public void Run_ProtectsExistingUnprotectedFileInPlace_AndRevealsOriginalKey()
    {
        using var tempDir = new TempDirectory();
        var path = tempDir.GetFilePath("k.key");
        var plaintextKey = RandomNumberGenerator.GetBytes(32);
        File.WriteAllBytes(path, plaintextKey);

        var storage = new InMemoryKeyInputStorage();
        var (exitCode, output, _) = Run(
            [path, "--material-identifier", "3", "--iterations", "2"],
            CreateKeySpecFactory(storage));

        Assert.Equal(0, exitCode);
        Assert.Contains("Key protected successfully", output);
        Assert.Equal(BlobSpec.TotalLength, new FileInfo(path).Length);

        var keySpec = CreateKeySpecFactory(storage)("HkdfGuard", 3, 2);
        Assert.Equal(plaintextKey, RevealProtectedKey(path, keySpec));
    }

    [Fact]
    public void Run_OnAlreadyProtectedFile_IsNoOp()
    {
        using var tempDir = new TempDirectory();
        var path = tempDir.GetFilePath("k.key");
        File.WriteAllBytes(path, RandomNumberGenerator.GetBytes(32));

        var factory = CreateKeySpecFactory(new InMemoryKeyInputStorage());
        Run([path, "--material-identifier", "1", "--iterations", "1"], factory);

        var (exitCode, output, _) = Run([path, "--material-identifier", "1", "--iterations", "1"], factory);

        Assert.Equal(0, exitCode);
        Assert.Contains("already protected", output);
    }

    [Fact]
    public void Run_WithDek_EncryptsDirectlyToFreshDestination_AndRevealsOriginalKey()
    {
        using var tempDir = new TempDirectory();
        var path = tempDir.GetFilePath("direct.key");
        var dekBytes = RandomNumberGenerator.GetBytes(32);
        var dekBase64 = Convert.ToBase64String(dekBytes);

        var storage = new InMemoryKeyInputStorage();
        var (exitCode, output, _) = Run(
            [path, "--dek", dekBase64, "--material-identifier", "5", "--iterations", "1"],
            CreateKeySpecFactory(storage));

        Assert.Equal(0, exitCode);
        Assert.Contains("Key protected successfully", output);

        var keySpec = CreateKeySpecFactory(storage)("HkdfGuard", 5, 1);
        Assert.Equal(dekBytes, RevealProtectedKey(path, keySpec));
    }

    [Fact]
    public void Run_WithDek_RefusesToOverwriteExistingDestination()
    {
        using var tempDir = new TempDirectory();
        var path = tempDir.GetFilePath("direct.key");
        File.WriteAllBytes(path, new byte[BlobSpec.TotalLength]);
        var dekBase64 = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

        var (exitCode, _, error) = Run([path, "--dek", dekBase64, "--material-identifier", "1", "--iterations", "1"]);

        Assert.Equal(1, exitCode);
        Assert.Contains("already exists", error);
    }

    [Fact]
    public void Run_UsesCustomServiceName()
    {
        using var tempDir = new TempDirectory();
        var path = tempDir.GetFilePath("k.key");
        var plaintextKey = RandomNumberGenerator.GetBytes(32);
        File.WriteAllBytes(path, plaintextKey);

        var storage = new InMemoryKeyInputStorage();
        var (exitCode, _, _) = Run(
            [path, "--material-identifier", "1", "--iterations", "1", "--service-name", "custom-svc"],
            CreateKeySpecFactory(storage));

        Assert.Equal(0, exitCode);

        var keySpec = CreateKeySpecFactory(storage)("custom-svc", 1, 1);
        Assert.Equal(plaintextKey, RevealProtectedKey(path, keySpec));
    }

    [Fact]
    public void Run_WithShortFormFlags_ProtectsExistingUnprotectedFileInPlace_AndRevealsOriginalKey()
    {
        using var tempDir = new TempDirectory();
        var path = tempDir.GetFilePath("k.key");
        var plaintextKey = RandomNumberGenerator.GetBytes(32);
        File.WriteAllBytes(path, plaintextKey);

        var storage = new InMemoryKeyInputStorage();
        var (exitCode, output, _) = Run(
            [path, "-mi", "3", "-i", "2", "-sn", "short-form-svc"],
            CreateKeySpecFactory(storage));

        Assert.Equal(0, exitCode);
        Assert.Contains("Key protected successfully", output);

        var keySpec = CreateKeySpecFactory(storage)("short-form-svc", 3, 2);
        Assert.Equal(plaintextKey, RevealProtectedKey(path, keySpec));
    }

    [Fact]
    public void Run_WithShortFormDekFlag_EncryptsDirectlyToFreshDestination_AndRevealsOriginalKey()
    {
        using var tempDir = new TempDirectory();
        var path = tempDir.GetFilePath("direct.key");
        var dekBytes = RandomNumberGenerator.GetBytes(32);
        var dekBase64 = Convert.ToBase64String(dekBytes);

        var storage = new InMemoryKeyInputStorage();
        var (exitCode, output, _) = Run(
            [path, "-d", dekBase64, "-mi", "5", "-i", "1"],
            CreateKeySpecFactory(storage));

        Assert.Equal(0, exitCode);
        Assert.Contains("Key protected successfully", output);

        var keySpec = CreateKeySpecFactory(storage)("HkdfGuard", 5, 1);
        Assert.Equal(dekBytes, RevealProtectedKey(path, keySpec));
    }
}
