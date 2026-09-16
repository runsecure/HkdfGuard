using HkdfGuard.Options;
using Microsoft.Extensions.DependencyInjection;

namespace HkdfGuard.DependencyInjection;

/// <summary>
/// Configures HkdfGuard services registered by IServiceCollection.AddHkdfGuard - the same shape
/// as ILoggingBuilder: extension methods configure the underlying IServiceCollection (via
/// Services) or this instance's CryptoComponentRegistry (via Registry), and return this same
/// builder so calls chain (e.g. builder.Configure(o => ...).BindConfiguration(section)).
/// </summary>
public interface IHkdfGuardBuilder
{
    /// <summary>
    /// The IServiceCollection AddHkdfGuard was called on.
    /// </summary>
    IServiceCollection Services { get; }

    /// <summary>
    /// The CryptoComponentRegistry the built KeyRing resolves its components from - the same
    /// instance registered as a singleton, so registering a custom component here (e.g.
    /// Registry.RegisterCipher(...)) is visible to the KeyRing built from this container.
    /// </summary>
    CryptoComponentRegistry Registry { get; }
}
