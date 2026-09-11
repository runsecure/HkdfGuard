namespace HkdfGuard.Options;

/// <summary>
/// Configuration for assembling a KeyRing: which named cryptographic components to use (see
/// CryptoComponentRegistry for the valid keys for each) and which independently-protected key
/// files to register into it. Intended to be bound from IConfiguration/appsettings via the
/// standard Options pattern (e.g. services.Configure&lt;HkdfGuardOptions&gt;(section)).
/// </summary>
public sealed class HkdfGuardOptions
{
    /// <summary>
    /// The service name used to scope this service's key material in OS-native secure storage,
    /// and bound into every signature this recipe computes/verifies.
    /// </summary>
    public string ServiceName { get; set; } = string.Empty;

    /// <summary>
    /// Selects the IKeyDerivationFunction implementation via CryptoComponentRegistry. Defaults to
    /// "Pbkdf2".
    /// </summary>
    public string KeyDerivation { get; set; } = "Pbkdf2";

    /// <summary>
    /// Selects the ISymmetricCipher implementation via CryptoComponentRegistry. Defaults to
    /// "AesGcm".
    /// </summary>
    public string Cipher { get; set; } = "AesGcm";

    /// <summary>
    /// Selects the IHash implementation via CryptoComponentRegistry. Defaults to "HmacSha256".
    /// </summary>
    public string Hash { get; set; } = "HmacSha256";

    /// <summary>
    /// Selects the IKeyWrapperFactory implementation via CryptoComponentRegistry. Defaults to
    /// "Hkdf".
    /// </summary>
    public string KeyWrapperFactory { get; set; } = "Hkdf";

    /// <summary>
    /// Selects the IKeyProtectorFactory implementation via CryptoComponentRegistry, used only to
    /// protect an ephemeral key's own freshly generated material - unused (and not validated)
    /// unless EphemeralKeys is non-empty. Defaults to "Default".
    /// </summary>
    public string KeyProtectorFactory { get; set; } = "Default";

    /// <summary>
    /// Every independently-protected key file to register into the built KeyRing.
    /// </summary>
    public List<KeyFileOptions> KeyFiles { get; set; } = [];

    /// <summary>
    /// Every ephemeral key (its own material generated fresh in memory on first use, never
    /// written to or read from disk - see EphemeralDataProtectionKey) to register into the built
    /// KeyRing.
    /// </summary>
    public List<EphemeralKeyOptions> EphemeralKeys { get; set; } = [];
}

/// <summary>
/// One entry for KeyRingBuilder.AddKeyFile - a single independently-protected key file (see
/// HkdfGuard.Initializer), with its own MaterialIdentifier/Iterations.
/// </summary>
public sealed class KeyFileOptions
{
    /// <summary>
    /// The KeyRing version to register this key under.
    /// </summary>
    public int Version { get; set; }

    /// <summary>
    /// Path to this version's protected key blob file.
    /// </summary>
    public string Path { get; set; } = string.Empty;

    /// <summary>
    /// The material identifier this key file was protected with - printed by
    /// HkdfGuard.Initializer when the file was created.
    /// </summary>
    public int MaterialIdentifier { get; set; }

    /// <summary>
    /// The iteration count this key file was protected with - printed by
    /// HkdfGuard.Initializer when the file was created.
    /// </summary>
    public int Iterations { get; set; }
}

/// <summary>
/// One entry for KeyRingBuilder.AddEphemeralKey - a key whose own material is generated fresh in
/// memory on first use and never written to or read from disk, with its own
/// MaterialIdentifier/Iterations governing the key-derivation input it still pulls from the same
/// IKeyInputStorage a durable key would use.
/// </summary>
public sealed class EphemeralKeyOptions
{
    /// <summary>
    /// The KeyRing version to register this key under.
    /// </summary>
    public int Version { get; set; }

    /// <summary>
    /// The material identifier this version's key-derivation input should use.
    /// </summary>
    public int MaterialIdentifier { get; set; }

    /// <summary>
    /// The iteration count this version's key-derivation input should use.
    /// </summary>
    public int Iterations { get; set; }
}
