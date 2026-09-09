using HkdfGuard.Abstractions;
using HkdfGuard.Core.Interop;

namespace HkdfGuard.Core.Cryptography;

/// <summary>
/// Assembles an IKeySpec pre-configured with this library's own default modules
/// (Pbkdf2KeyDerivationFunction backed by the platform-appropriate IKeyInputStorage,
/// AesGcmCipher, HmacSha256Hash). CryptoRecipeBuilder itself has no built-in defaults so it can
/// be reused with any implementations - this is the convenience entry point for this library's
/// own. KeyWrapperFactory/KeyProtectorFactory are exposed alongside as stateless singletons,
/// since minting an IKeyWrapper/IKeyProtector from the built IKeySpec is their job, not the
/// spec's.
/// </summary>
public static class DefaultCryptoRecipe
{
    public static IKeyWrapperFactory KeyWrapperFactory { get; } = new HkdfKeyWrapperFactory();

    public static IKeyProtectorFactory KeyProtectorFactory { get; } = new KeyProtectorFactory();

    public static IKeySpec Create(string serviceName, int materialIdentifier, int iterations)
        => new CryptoRecipeBuilder()
            .WithServiceName(serviceName)
            .WithKeyDerivation(new Pbkdf2KeyDerivationFunction(KeyInputStorageFactory.Create(serviceName)))
            .WithCipher(new AesGcmCipher())
            .WithHash(new HmacSha256Hash())
            .WithMaterialIdentifier(materialIdentifier)
            .WithIterations(iterations)
            .Build();
}
