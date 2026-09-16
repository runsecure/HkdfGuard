using Microsoft.Extensions.Options;

namespace HkdfGuard.Options;

/// <summary>
/// Validates HkdfGuardOptions before it's used to build a KeyRing - plugs into the standard
/// Options validation pipeline (register as
/// services.AddSingleton&lt;IValidateOptions&lt;HkdfGuardOptions&gt;, HkdfGuardOptionsValidator&gt;(),
/// typically alongside services.AddOptions&lt;HkdfGuardOptions&gt;().ValidateOnStart() so
/// misconfiguration fails at startup rather than at first use).
///
/// Only checks what's structurally required to assemble a KeyRing at all (required strings,
/// well-formed key files, no duplicate versions). Whether a given component name is actually
/// registered is checked later by HkdfGuardKeyRingFactory.Build - a CryptoComponentRegistry is a
/// separate, per-caller-configured object this validator has no access to, and can legitimately
/// be extended after Options are bound.
/// </summary>
public sealed class HkdfGuardOptionsValidator : IValidateOptions<HkdfGuardOptions>
{
    public ValidateOptionsResult Validate(string? name, HkdfGuardOptions options)
    {
        var failures = new List<string>();

        if (string.IsNullOrWhiteSpace(options.ServiceName))
            failures.Add($"{nameof(HkdfGuardOptions.ServiceName)} is required.");

        if (string.IsNullOrWhiteSpace(options.KeyDerivation))
            failures.Add($"{nameof(HkdfGuardOptions.KeyDerivation)} is required.");

        if (string.IsNullOrWhiteSpace(options.Cipher))
            failures.Add($"{nameof(HkdfGuardOptions.Cipher)} is required.");

        if (string.IsNullOrWhiteSpace(options.Hash))
            failures.Add($"{nameof(HkdfGuardOptions.Hash)} is required.");

        if (string.IsNullOrWhiteSpace(options.KeyWrapperFactory))
            failures.Add($"{nameof(HkdfGuardOptions.KeyWrapperFactory)} is required.");

        // Shared across KeyFiles and EphemeralKeys - KeyRing.Add rejects a duplicate version
        // regardless of which source registered it first.
        var seenVersions = new HashSet<int>();

        if (options.KeyFiles is null)
        {
            failures.Add($"{nameof(HkdfGuardOptions.KeyFiles)} must not be null.");
        }
        else
        {
            for (var i = 0; i < options.KeyFiles.Count; i++)
            {
                var keyFile = options.KeyFiles[i];
                var prefix = $"{nameof(HkdfGuardOptions.KeyFiles)}[{i}]";

                if (string.IsNullOrWhiteSpace(keyFile.Path))
                    failures.Add($"{prefix}.{nameof(KeyFileOptions.Path)} is required.");

                if (keyFile.MaterialIdentifier < 1)
                    failures.Add($"{prefix}.{nameof(KeyFileOptions.MaterialIdentifier)} ({keyFile.MaterialIdentifier}) must be a positive integer.");

                if (keyFile.Iterations < 1)
                    failures.Add($"{prefix}.{nameof(KeyFileOptions.Iterations)} ({keyFile.Iterations}) must be a positive integer.");

                if (!seenVersions.Add(keyFile.Version))
                    failures.Add($"{prefix}.{nameof(KeyFileOptions.Version)} ({keyFile.Version}) is registered by more than one key.");
            }
        }

        if (options.EphemeralKeys is null)
        {
            failures.Add($"{nameof(HkdfGuardOptions.EphemeralKeys)} must not be null.");
        }
        else
        {
            for (var i = 0; i < options.EphemeralKeys.Count; i++)
            {
                var ephemeralKey = options.EphemeralKeys[i];
                var prefix = $"{nameof(HkdfGuardOptions.EphemeralKeys)}[{i}]";

                if (ephemeralKey.MaterialIdentifier < 1)
                    failures.Add($"{prefix}.{nameof(EphemeralKeyOptions.MaterialIdentifier)} ({ephemeralKey.MaterialIdentifier}) must be a positive integer.");

                if (ephemeralKey.Iterations < 1)
                    failures.Add($"{prefix}.{nameof(EphemeralKeyOptions.Iterations)} ({ephemeralKey.Iterations}) must be a positive integer.");

                if (!seenVersions.Add(ephemeralKey.Version))
                    failures.Add($"{prefix}.{nameof(EphemeralKeyOptions.Version)} ({ephemeralKey.Version}) is registered by more than one key.");
            }
        }

        return failures.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(failures);
    }
}
