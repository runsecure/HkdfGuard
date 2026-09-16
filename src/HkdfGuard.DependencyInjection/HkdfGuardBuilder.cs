using HkdfGuard.Options;
using Microsoft.Extensions.DependencyInjection;

namespace HkdfGuard.DependencyInjection;

/// <summary>
/// Default IHkdfGuardBuilder. Internal: only IServiceCollection.AddHkdfGuard constructs one, so
/// Registry is always the same instance registered into the container it wraps.
/// </summary>
internal sealed class HkdfGuardBuilder(IServiceCollection services, CryptoComponentRegistry registry) : IHkdfGuardBuilder
{
    public IServiceCollection Services { get; } = services;
    public CryptoComponentRegistry Registry { get; } = registry;
}
