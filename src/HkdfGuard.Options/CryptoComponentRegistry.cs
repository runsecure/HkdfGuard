using HkdfGuard.Abstractions;
using HkdfGuard.Core.Cryptography;
using HkdfGuard.Core.Interop;

namespace HkdfGuard.Options;

/// <summary>
/// Maps the short string keys used in HkdfGuardOptions to actual crypto component instances.
/// Pre-seeded with this library's built-in implementations (Pbkdf2/AesGcm/HmacSha512/Hkdf), but
/// instance-based and mutable rather than a fixed set - other developers can Register their own
/// factory under a new name to add an option, or under an existing name (e.g. "AesGcm") to
/// replace what that name resolves to, without forking this library. Registration is a
/// factory delegate rather than a bare type name/reflection: some components
/// (Pbkdf2KeyDerivationFunction) need real constructor dependencies (a platform-specific
/// IKeyInputStorage) that a type name alone can't express safely, and a delegate lets a
/// replacement supply whatever construction logic it needs.
/// </summary>
public sealed class CryptoComponentRegistry
{
    private readonly Dictionary<string, Func<string, IKeyDerivationFunction>> _keyDerivations = new();
    private readonly Dictionary<string, Func<ISymmetricCipher>> _ciphers = new();
    private readonly Dictionary<string, Func<IHash>> _hashes = new();
    private readonly Dictionary<string, Func<IKeyWrapperFactory>> _keyWrapperFactories = new();

    public CryptoComponentRegistry()
    {
        RegisterKeyDerivation("Pbkdf2", serviceName => new Pbkdf2KeyDerivationFunction(KeyInputStorageFactory.Create(serviceName)));
        RegisterCipher("AesGcm", () => new AesGcmCipher());
        RegisterHash("HmacSha512", () => new HmacSha512Hash());
        RegisterKeyWrapperFactory("Hkdf", () => new HkdfKeyWrapperFactory());
    }

    /// <summary>
    /// Registers a factory for an IKeyDerivationFunction under name, adding a new option or
    /// replacing an existing one (including a built-in) if name is already registered.
    /// </summary>
    public void RegisterKeyDerivation(string name, Func<string, IKeyDerivationFunction> factory)
        => _keyDerivations[name] = factory;

    /// <summary>
    /// Registers a factory for an ISymmetricCipher under name, adding a new option or replacing
    /// an existing one (including a built-in) if name is already registered.
    /// </summary>
    public void RegisterCipher(string name, Func<ISymmetricCipher> factory)
        => _ciphers[name] = factory;

    /// <summary>
    /// Registers a factory for an IHash under name, adding a new option or replacing an existing
    /// one (including a built-in) if name is already registered.
    /// </summary>
    public void RegisterHash(string name, Func<IHash> factory)
        => _hashes[name] = factory;

    /// <summary>
    /// Registers a factory for an IKeyWrapperFactory under name, adding a new option or replacing
    /// an existing one (including a built-in) if name is already registered.
    /// </summary>
    public void RegisterKeyWrapperFactory(string name, Func<IKeyWrapperFactory> factory)
        => _keyWrapperFactories[name] = factory;

    public IKeyDerivationFunction CreateKeyDerivation(string name, string serviceName)
        => Resolve(_keyDerivations, name, "KeyDerivation")(serviceName);

    public ISymmetricCipher CreateCipher(string name)
        => Resolve(_ciphers, name, "Cipher")();

    public IHash CreateHash(string name)
        => Resolve(_hashes, name, "Hash")();

    public IKeyWrapperFactory CreateKeyWrapperFactory(string name)
        => Resolve(_keyWrapperFactories, name, "KeyWrapperFactory")();

    private static TFactory Resolve<TFactory>(Dictionary<string, TFactory> registrations, string name, string category)
        where TFactory : Delegate
    {
        if (registrations.TryGetValue(name, out var factory))
            return factory;

        throw new NotSupportedException(
            $"Unknown {category} '{name}'. Registered: {string.Join(", ", registrations.Keys)}.");
    }
}
