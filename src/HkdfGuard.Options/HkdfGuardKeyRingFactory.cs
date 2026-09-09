using Microsoft.Extensions.Options;
using HkdfGuard.Abstractions;
using HkdfGuard.DataProtectionKey.KeyTracking;

namespace HkdfGuard.Options;

/// <summary>
/// Turns HkdfGuardOptions into a populated KeyRing: resolves the named cryptographic components
/// via a CryptoComponentRegistry (this library's built-in defaults unless a customized registry
/// with extra/replacement registrations is supplied), assembles them into a CryptoRecipeBuilder
/// shared across every registered key file, and runs a KeyRingBuilder to read/verify/wrap each
/// one. This is the single place application startup code needs to call to go from configuration
/// straight to a ready-to-use KeyRing.
/// </summary>
public sealed class HkdfGuardKeyRingFactory(CryptoComponentRegistry? registry = null)
{
    private readonly CryptoComponentRegistry _registry = registry ?? new CryptoComponentRegistry();

    /// <summary>
    /// Builds a KeyRing from already-bound options.
    /// </summary>
    /// <exception cref="NotSupportedException">A configured component name isn't registered in this factory's CryptoComponentRegistry</exception>
    /// <exception cref="System.Security.Cryptography.CryptographicException">A key file failed signature verification</exception>
    public KeyRing Build(HkdfGuardOptions options)
    {
        var recipeBuilder = new CryptoRecipeBuilder()
            .WithServiceName(options.ServiceName)
            .WithKeyDerivation(_registry.CreateKeyDerivation(options.KeyDerivation, options.ServiceName))
            .WithCipher(_registry.CreateCipher(options.Cipher))
            .WithHash(_registry.CreateHash(options.Hash));

        var keyWrapperFactory = _registry.CreateKeyWrapperFactory(options.KeyWrapperFactory);

        var keyRingBuilder = new KeyRingBuilder()
            .WithCryptoRecipe(recipeBuilder)
            .WithKeyWrapperFactory(keyWrapperFactory);

        foreach (var keyFile in options.KeyFiles)
            keyRingBuilder.AddKeyFile(keyFile.Version, keyFile.Path, keyFile.MaterialIdentifier, keyFile.Iterations);

        return keyRingBuilder.Build();
    }

    /// <summary>
    /// Builds a KeyRing from an IOptions&lt;HkdfGuardOptions&gt;, as bound by the standard Options
    /// pattern (e.g. services.Configure&lt;HkdfGuardOptions&gt;(configuration.GetSection("HkdfGuard"))).
    /// </summary>
    public KeyRing Build(IOptions<HkdfGuardOptions> options)
        => Build(options.Value);
}
