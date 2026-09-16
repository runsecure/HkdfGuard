using System.Collections.Concurrent;
using HkdfGuard.DataProtectionKey.Diagnostics;
using HkdfGuard.DataProtectionKey.Protector;
using HkdfGuard.Abstractions;

namespace HkdfGuard.DataProtectionKey.KeyTracking;

/// <summary>
/// Tracks IDataProtectionKey instances by version for highly concurrent workloads (thousands of
/// operations per second). Get is served straight off a ConcurrentDictionary, so the hot read
/// path never blocks - no telemetry on that path either, only on a Get miss, since that's the
/// exceptional case and startup overhead there is irrelevant. Add is serialized through a
/// SemaphoreSlim - key registration only happens at startup/rotation, not per-operation, so the
/// gate (and its telemetry) costs nothing where it matters and keeps the door open for an
/// async-loaded Add later (SemaphoreSlim supports WaitAsync; lock does not).
///
/// The ring tracks its own current version intrinsically: whichever registered version number is
/// highest becomes CurrentVersion, automatically, the moment it's Added - there is no separate
/// call to designate one, so it can never fall out of sync with what's actually registered.
/// </summary>
public sealed class KeyRing(IEncryptedFormatProvider formatProvider)
{
    private const int NoCurrentVersion = int.MinValue;

    private readonly ConcurrentDictionary<int, IDataProtectionKey> _keysByVersion = new();
    private readonly SemaphoreSlim _addGate = new(1, 1);
    private volatile int _currentVersion = NoCurrentVersion;

    /// <summary>
    /// The highest version registered so far - what Encrypt-side operations (e.g.
    /// DataProtector.Encrypt) protect new data with.
    /// </summary>
    /// <exception cref="InvalidOperationException">No key has been added yet</exception>
    public int CurrentVersion
    {
        get
        {
            var current = _currentVersion;
            if (current == NoCurrentVersion)
                throw new InvalidOperationException("No current version has been set. Add a key first.");

            return current;
        }
    }

    /// <summary>
    /// Registers a key for the given version. If version is higher than every version registered
    /// so far, it intrinsically becomes the new CurrentVersion.
    /// </summary>
    /// <param name="version">The key version to register</param>
    /// <param name="key">The IDataProtectionKey for this version</param>
    /// <exception cref="ArgumentException">A key for this version is already registered</exception>
    public void Add(int version, IDataProtectionKey key)
    {
        using var activity = DataProtectionDiagnostics.ActivitySource.StartActivity("KeyRing.Add");

        _addGate.Wait();
        try
        {
            if (!_keysByVersion.TryAdd(version, key))
                throw new ArgumentException($"A key for version {version} is already registered.", nameof(version));

            var becameCurrent = _currentVersion == NoCurrentVersion || version > _currentVersion;
            if (becameCurrent)
                _currentVersion = version;

            if (DataProtectionDiagnostics.EnableSensitiveLogging)
                DataProtectionDiagnostics.LogSensitiveOperation(activity, "KeyRing.Add",
                    ("version", version), ("becameCurrent", becameCurrent));
        }
        catch (Exception ex)
        {
            DataProtectionDiagnostics.RecordException(activity, ex);
            throw;
        }
        finally
        {
            _addGate.Release();
        }
    }

    /// <summary>
    /// Retrieves the key registered for the given version
    /// </summary>
    /// <param name="version">The key version to retrieve</param>
    /// <returns>The registered IDataProtectionKey</returns>
    /// <exception cref="KeyNotFoundException">No key is registered for this version</exception>
    public IDataProtectionKey Get(int version)
    {
        if (_keysByVersion.TryGetValue(version, out var key))
            return key;

        var notFound = new KeyNotFoundException($"No key is registered for version {version}.");
        using var activity = DataProtectionDiagnostics.ActivitySource.StartActivity("KeyRing.Get");
        DataProtectionDiagnostics.RecordException(activity, notFound);
        throw notFound;
    }

    /// <summary>
    /// Attempts to retrieve the key registered for the given version without throwing - for the
    /// high-frequency hot path, where exception overhead (and telemetry) on a routine miss is
    /// unacceptable.
    /// </summary>
    /// <param name="version">The key version to retrieve</param>
    /// <param name="key">The registered IDataProtectionKey, if found</param>
    /// <returns>True if a key was registered for this version</returns>
    public bool TryGet(int version, out IDataProtectionKey? key)
        => _keysByVersion.TryGetValue(version, out key);

    /// <summary>
    /// Retrieves CurrentVersion together with its IDataProtectionKey atomically - what
    /// Encrypt-side operations (e.g. DataProtector.Encrypt) resolve fresh on every call, so they
    /// always reflect the latest rotation rather than a version captured once at construction.
    /// </summary>
    /// <returns>The current version and its registered IDataProtectionKey</returns>
    /// <exception cref="InvalidOperationException">No key has been added yet</exception>
    public (int Version, IDataProtectionKey Key) GetCurrent()
    {
        try
        {
            var version = CurrentVersion;
            return (version, Get(version));
        }
        catch (InvalidOperationException ex)
        {
            using var activity = DataProtectionDiagnostics.ActivitySource.StartActivity("KeyRing.GetCurrent");
            DataProtectionDiagnostics.RecordException(activity, ex);
            throw;
        }
    }

    /// <summary>
    /// Creates an IDataProtector bound to this KeyRing - the only way to obtain one, since
    /// DataProtector's constructor is internal to this assembly. Encrypt resolves CurrentVersion
    /// fresh via GetCurrent on every call (not a version captured once here), and formats/parses
    /// via the IEncryptedFormatProvider this ring was constructed with.
    /// </summary>
    /// <param name="name">Used as this protector's Additional Auth Data on every Encrypt/Decrypt</param>
    public IDataProtector CreateProtector(string name)
        => new DataProtector(name, this, formatProvider);
}
