namespace HkdfGuard.Abstractions;

/// <summary>
/// Mints an IKeyWrapper over an existing, already-validated protected key blob (see
/// KeyBlobFactory.TryLoad), configured by a given IKeySpec. This is the sole place that turns an
/// IKeySpec + IKeyBlob into a usable IKeyWrapper, without callers depending on any concrete
/// IKeyWrapper implementation.
/// </summary>
public interface IKeyWrapperFactory
{
    public IKeyWrapper Create(IKeySpec spec, IKeyBlob blob);
}
