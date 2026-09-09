namespace HkdfGuard.Abstractions;

/// <summary>
/// Mints an IKeyProtector for first-time initialization from a configured IKeySpec (which carries
/// the material identifier and iteration count to use) plus a salt. This is the sole place that
/// turns an IKeySpec + salt into a usable IKeyProtector, without callers depending on any
/// concrete IKeyProtector implementation.
/// </summary>
public interface IKeyProtectorFactory
{
    public IKeyProtector Create(IKeySpec spec, byte[] salt);
}
