using System.Security.Cryptography;
using HkdfGuard.Abstractions;
using HkdfGuard.Core.Primitives;
using HkdfGuard.DataProtectionKey.FormatProvider;
using HkdfGuard.DataProtectionKey.Key;

namespace HkdfGuard.DataProtectionKey.KeyTracking;

/// <summary>
/// Builds a KeyRing from keys that live on disk in encrypted form, suitable for registering as a
/// singleton in a DI container at startup. There is no shared/master key - every registered key
/// file is independently protected (see HkdfGuard.Initializer), with its own
/// MaterialIdentifier and Iterations, and is validated and minted into its own IKeyWrapper when
/// Build runs. Nothing here ever holds a version's key unwrapped - each IDataProtectionKey
/// derives/reveals it fresh on every operation.
/// </summary>
public sealed class KeyRingBuilder
{
    private readonly List<(int Version, string Path, int MaterialIdentifier, int Iterations)> _versionFiles = [];
    private ICryptoRecipeBuilder? _recipeBuilder;
    private IKeyWrapperFactory? _keyWrapperFactory;
    private IEncryptedFormatProvider _formatProvider = new DefaultFormatProvider();
    private KeyBlobSpec _blobSpec = new(saltLength: 64, encryptedKeySaltLength: 32, encryptedKeyValueLength: 60, signatureLength: 32);

    /// <summary>
    /// Supplies the ICryptoRecipeBuilder used to build a per-file IKeySpec when Build runs. Its
    /// ServiceName/KeyDerivation/Cipher/Hash are shared across every registered key file, while
    /// MaterialIdentifier/Iterations are overridden per file from each AddKeyFile call.
    /// </summary>
    public KeyRingBuilder WithCryptoRecipe(ICryptoRecipeBuilder recipeBuilder)
    {
        _recipeBuilder = recipeBuilder;
        return this;
    }

    /// <summary>
    /// Supplies the IKeyWrapperFactory used to mint each key file's IKeyWrapper.
    /// </summary>
    public KeyRingBuilder WithKeyWrapperFactory(IKeyWrapperFactory keyWrapperFactory)
    {
        _keyWrapperFactory = keyWrapperFactory;
        return this;
    }

    /// <summary>
    /// Describes each key file's on-disk field layout. Defaults to the layout
    /// HkdfGuard.Initializer produces (64/32/60/32 byte Salt/EncryptedKeySalt/
    /// EncryptedKeyValue/Signature fields) - only override this if the key files were protected
    /// with a different KeyBlobSpec.
    /// </summary>
    public KeyRingBuilder WithBlobSpec(KeyBlobSpec blobSpec)
    {
        _blobSpec = blobSpec;
        return this;
    }

    /// <summary>
    /// Overrides the IEncryptedFormatProvider the built KeyRing uses for CreateProtector.
    /// Defaults to DefaultFormatProvider.
    /// </summary>
    public KeyRingBuilder WithFormatProvider(IEncryptedFormatProvider formatProvider)
    {
        _formatProvider = formatProvider;
        return this;
    }

    /// <summary>
    /// Registers a version whose independently-protected key file will be read and verified when
    /// Build runs. materialIdentifier/iterations are this file's own - unrelated to any other
    /// registered key file, and must match what that specific file was protected with. The
    /// highest version registered across all AddKeyFile calls intrinsically becomes the built
    /// KeyRing's CurrentVersion.
    /// </summary>
    /// <param name="version">The KeyRing version to register this key under</param>
    /// <param name="path">Path to this version's protected key blob file</param>
    /// <param name="materialIdentifier">The material identifier this key file was protected with</param>
    /// <param name="iterations">The iteration count this key file was protected with</param>
    public KeyRingBuilder AddKeyFile(int version, string path, int materialIdentifier, int iterations)
    {
        _versionFiles.Add((version, path, materialIdentifier, iterations));
        return this;
    }

    /// <summary>
    /// Reads, verifies, and wraps each registered key file, returning a populated KeyRing.
    /// </summary>
    /// <exception cref="InvalidOperationException">No crypto recipe or key wrapper factory was configured</exception>
    /// <exception cref="CryptographicException">A key file failed signature verification</exception>
    public KeyRing Build()
    {
        if (_recipeBuilder is null)
            throw new InvalidOperationException("A crypto recipe is required - call WithCryptoRecipe first.");

        if (_keyWrapperFactory is null)
            throw new InvalidOperationException("A key wrapper factory is required - call WithKeyWrapperFactory first.");

        var ring = new KeyRing(_formatProvider);
        foreach (var (version, path, materialIdentifier, iterations) in _versionFiles)
        {
            var keySpec = _recipeBuilder
                .WithMaterialIdentifier(materialIdentifier)
                .WithIterations(iterations)
                .Build();

            var blobBytes = File.ReadAllBytes(path);
            if (!KeyBlobFactory.TryLoad(blobBytes, keySpec, _blobSpec, out var blob))
                throw new CryptographicException($"Key file at '{path}' (version {version}) failed signature verification.");

            var keyWrapper = _keyWrapperFactory.Create(keySpec, blob!);
            ring.Add(version, new KeyWrappedDataProtectionKey(keyWrapper, keySpec.Cipher));
        }

        return ring;
    }
}
