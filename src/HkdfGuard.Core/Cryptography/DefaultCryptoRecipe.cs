using HkdfGuard.Abstractions;
using HkdfGuard.Core.Interop;

namespace HkdfGuard.Core.Cryptography;

/// <summary>
/// Assembles an IKeySpec pre-configured with this library's own default modules
/// (Pbkdf2KeyDerivationFunction backed by the platform-appropriate IKeyInputStorage,
/// AesGcmCipher, HmacSha512Hash). CryptoRecipeBuilder itself has no built-in defaults so it can
/// be reused with any implementations - this is the convenience entry point for this library's
/// own. KeyWrapperFactory is exposed alongside as a stateless singleton, since minting an
/// IKeyWrapper from the built IKeySpec is its job, not the spec's; an IKeyProtector is instead
/// constructed directly from an IKeySpec plus a salt (see KeyProtector), so there's no equivalent
/// factory to expose for it.
/// </summary>
public static class DefaultCryptoRecipe
{
    public static IKeyWrapperFactory KeyWrapperFactory { get; } = new HkdfKeyWrapperFactory();

    public static IKeySpec Create(string serviceName, int materialIdentifier, int iterations)
        => new CryptoRecipeBuilder()
            .WithServiceName(serviceName)
            .WithKeyDerivation(new Pbkdf2KeyDerivationFunction(KeyInputStorageFactory.Create(serviceName)))
            .WithCipher(new AesGcmCipher())
            .WithHash(new HmacSha512Hash())
            .WithMaterialIdentifier(materialIdentifier)
            .WithIterations(iterations)
            .Build();
}
