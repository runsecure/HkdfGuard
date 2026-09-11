using HkdfGuard.DataProtectionKey.KeyTracking;
using HkdfGuard.Options;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace HkdfGuard.DependencyInjection;

/// <summary>
/// Entry point for registering HkdfGuard into an IServiceCollection - the same shape as
/// IServiceCollection.AddLogging: registers everything needed to resolve a KeyRing (a
/// CryptoComponentRegistry, HkdfGuardOptions plumbing, and the KeyRing itself, built lazily on
/// first resolution via HkdfGuardKeyRingFactory), then hands an IHkdfGuardBuilder to configure
/// for callers who want to bind options or register custom crypto components.
/// </summary>
public static class HkdfGuardServiceCollectionExtensions
{
    /// <summary>
    /// Registers HkdfGuard with its default (unconfigured) HkdfGuardOptions - callers relying on
    /// this overload alone must configure ServiceName etc. themselves, e.g. via
    /// services.Configure&lt;HkdfGuardOptions&gt;(...) directly.
    /// </summary>
    public static IServiceCollection AddHkdfGuard(this IServiceCollection services)
        => services.AddHkdfGuard(_ => { });

    /// <summary>
    /// Registers HkdfGuard and runs configure against the resulting IHkdfGuardBuilder to bind
    /// options and/or register custom crypto components before returning.
    /// </summary>
    public static IServiceCollection AddHkdfGuard(this IServiceCollection services, Action<IHkdfGuardBuilder> configure)
    {
        services.AddOptions<HkdfGuardOptions>();
        services.TryAddSingleton<IValidateOptions<HkdfGuardOptions>, HkdfGuardOptionsValidator>();

        var builder = new HkdfGuardBuilder(services, new CryptoComponentRegistry());
        services.TryAddSingleton(builder.Registry);

        services.TryAddSingleton(sp => new HkdfGuardKeyRingFactory(sp.GetRequiredService<CryptoComponentRegistry>())
            .Build(sp.GetRequiredService<IOptions<HkdfGuardOptions>>()));

        configure(builder);
        return services;
    }
}
