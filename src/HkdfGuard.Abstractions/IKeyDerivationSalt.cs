namespace HkdfGuard.Abstractions;

public interface IKeyDerivationSalt
{
    /// <summary>
    /// The Salt to use in Key Derivation
    /// </summary>
    public ReadOnlySpan<byte> AsSpan();
}
