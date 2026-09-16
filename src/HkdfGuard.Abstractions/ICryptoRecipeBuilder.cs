namespace HkdfGuard.Abstractions;

/// <summary>
/// Fluent builder that chains together the modules used for actual encryption (key derivation,
/// symmetric cipher, hash - key storage is an internal dependency of key derivation, not a
/// separately configurable module here), and emits an IKeySpec - a reusable recipe describing
/// how keys for this service should be derived/protected. Minting an IKeyWrapper from the
/// resulting IKeySpec is IKeyWrapperFactory's job, held and used separately from this builder;
/// an IKeyProtector is instead constructed directly from the IKeySpec plus a salt. Depends only
/// on interfaces, so it isn't tied to any concrete crypto implementation and can be reused
/// outside this library.
/// </summary>
public interface ICryptoRecipeBuilder
{
    public ICryptoRecipeBuilder WithServiceName(string serviceName);

    public ICryptoRecipeBuilder WithKeyDerivation(IKeyDerivationFunction keyDerivation);

    public ICryptoRecipeBuilder WithCipher(ISymmetricCipher cipher);

    public ICryptoRecipeBuilder WithHash(IHash hash);

    /// <summary>
    /// Sets the material identifier this spec's key derivation should use. Signatures computed
    /// over it (e.g. by KeyBlobFactory) protect against a blob being loaded under a spec
    /// configured with a different identifier than the one it was created with.
    /// </summary>
    public ICryptoRecipeBuilder WithMaterialIdentifier(int materialIdentifier);

    /// <summary>
    /// Sets the iteration count this spec's key derivation should use.
    /// </summary>
    public ICryptoRecipeBuilder WithIterations(int iterations);

    /// <summary>
    /// Builds the configured IKeySpec. Requires a service name, key derivation, cipher, hash, a
    /// material identifier, and an iteration count to have been configured - there are no
    /// implicit defaults.
    /// </summary>
    public IKeySpec Build();
}
