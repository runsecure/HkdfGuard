using HkdfGuard.Options;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace HkdfGuard.DependencyInjection;

/// <summary>
/// Extension methods for IHkdfGuardBuilder - the ILoggingBuilder-style ecosystem
/// (builder.AddConsole(), builder.SetMinimumLevel(...)) HkdfGuard's own builder supports.
/// </summary>
public static class HkdfGuardBuilderExtensions
{
    /// <summary>
    /// Configures HkdfGuardOptions imperatively.
    /// </summary>
    public static IHkdfGuardBuilder Configure(this IHkdfGuardBuilder builder, Action<HkdfGuardOptions> configureOptions)
    {
        builder.Services.Configure(configureOptions);
        return builder;
    }

    /// <summary>
    /// Binds HkdfGuardOptions from configuration (e.g. configuration.GetSection("HkdfGuard")).
    /// </summary>
    public static IHkdfGuardBuilder BindConfiguration(this IHkdfGuardBuilder builder, IConfiguration configuration)
    {
        builder.Services.Configure<HkdfGuardOptions>(configuration);
        return builder;
    }
}
