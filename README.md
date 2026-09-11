# HkdfGuard

A C# library for protecting data-at-rest encryption keys using OS-native secure storage (macOS
Keychain, Windows Credential Manager, Linux systemd-creds/keyutils) combined with HKDF/PBKDF2 key
derivation and AES-GCM. Protected keys are stored as small, self-contained, signed **key blob**
files - never as plaintext - and are read back into a `KeyRing` that application code uses to
encrypt/decrypt strings and binary data, with automatic key-version tracking and purpose-scoped
Additional Authenticated Data (AAD).

## Key concepts

- **No plaintext key ever touches disk.** `HkdfGuard.Initializer` reads a raw 32-byte key file
  once, protects it into a signed key blob, and overwrites the original file.
- **No shared master key.** Every protected key file is independent - it has its own salt,
  material identifier, and iteration count. Compromising or rotating one key file has no effect
  on any other.
- **OS-native secure storage backs key derivation.** The actual secret backing each derived key
  lives in the platform's secure storage (Keychain/Credential Manager/systemd-creds), looked up by
  service name + material identifier - the on-disk blob alone is not enough to decrypt anything.
- **Versioned, rotatable keys via `KeyRing`.** A `KeyRing` tracks any number of independently
  protected keys by an integer version. The highest version added automatically becomes the
  ring's `CurrentVersion` - no separate "mark as current" step, so it can never drift out of sync
  with what's actually registered.
- **Purpose-scoped protectors.** `IDataProtector` binds a `name` (purpose) to every operation as
  AAD, so a value protected for one purpose can never be decrypted under another - even using the
  same underlying key.
- **Extensible crypto components.** `CryptoComponentRegistry` maps short string names (e.g.
  `"AesGcm"`, `"Pbkdf2"`) to concrete implementations. Consumers can register additional
  implementations or replace the built-in ones without forking the library.
- **Ephemeral, in-memory-only keys.** `EphemeralDataProtectionKey` generates and protects its own
  key entirely in memory - useful when a key only needs to live for the lifetime of a process or
  object, with no durable artifact on disk.
- **Span-based, allocation-conscious API.** Byte and char spans are used throughout; secrets are
  zeroed immediately after use and never returned as strings except for the final,
  already-encrypted, Base64-formatted output.
- **Built-in telemetry.** Every library emits `System.Diagnostics.ActivitySource` activities
  (OpenTelemetry-compatible) with exceptions recorded on failure, and an opt-in sensitive-logging
  mode that emits operation metadata (never raw key/plaintext/ciphertext bytes).

## Solution layout

| Project | Purpose |
|---|---|
| `HkdfGuard.Abstractions` | Interfaces and pure data types only (`IKeySpec`, `IKeyWrapper`, `IKeyProtector`, `IKeyBlob`, `IDataProtectionKey`, `IDataProtector`, `IEncryptedFormatProvider`, `KeyBlobSpec`, `KeyTrackingValue`, `CryptoRecipeBuilder`). No dependency on `HkdfGuard.Core`, so it can be reused independently. |
| `HkdfGuard.Core` | Concrete crypto implementations (`AesGcmCipher`, `Pbkdf2KeyDerivationFunction`, `HmacSha256Hash`, `HkdfKeyWrapper`, `KeyProtector`), the signed key blob format (`KeyBlobFactory`, `FlexibleKeyBlob`), and OS-native `IKeyInputStorage` implementations for macOS/Windows/Linux. |
| `HkdfGuard.DataProtectionKey` | The application-facing API: `KeyRing`, `KeyRingBuilder`, `IDataProtector`/`DataProtector`, `KeyWrappedDataProtectionKey`, `EphemeralDataProtectionKey`, and the default `enc::v{version}::{base64}` wire format. |
| `HkdfGuard.Initializer` | A `dotnet tool` (`hkdfguard-init`) that protects a raw 32-byte key file on disk into a signed key blob. |
| `HkdfGuard.Options` | Binds `HkdfGuardOptions` from `IConfiguration`/JSON via the standard .NET Options pattern, resolves named crypto components through `CryptoComponentRegistry`, and builds a `KeyRing` in one call via `HkdfGuardKeyRingFactory`. Includes `HkdfGuardOptionsValidator` (`IValidateOptions<HkdfGuardOptions>`). |
| `HkdfGuard.Core.Test`, `HkdfGuard.DataProtectionKey.Test`, `HkdfGuard.Options.Test` | xUnit test suites, maintained at full line/branch coverage for their respective projects. |

Requires **.NET 10** (`net10.0`).

## How a protected key blob works

A protected key file is a fixed-layout binary blob:

```
[ Salt | EncryptedKeySalt | EncryptedKeyValue | Signature ]
  64 B         32 B               60 B            32 B      (default layout)
```

- **Salt** is combined with a per-message nonce and OS-backed key material to derive an AES-256
  key via PBKDF2 (`Pbkdf2KeyDerivationFunction`), independently for every Encrypt/Decrypt call -
  no derived key is ever reused across messages.
- **EncryptedKeySalt**/**EncryptedKeyValue** hold the originally-protected 32-byte key, wrapped via
  the same scheme at protect-time (`HkdfGuard.Initializer`).
- **Signature** is an HMAC over `Salt + MaterialIdentifier + Iterations`, verified on load
  (`KeyBlobFactory.TryLoad`). `MaterialIdentifier`/`Iterations` are **not** stored in the blob
  itself - they live in the `IKeySpec` used to load it, and the signature fails to verify if they
  don't match what the blob was actually protected with. This is why `HkdfGuard.Initializer`
  prints the material identifier/iteration values it chose: they must be supplied again whenever
  the key is loaded back.

Loading a blob is a one-time cost: signature verification happens once, when the blob is read and
turned into an `IKeyWrapper`, not on every subsequent Encrypt/Decrypt call.

## Getting started

### 1. Protect a raw key file

```bash
dotnet tool install --global HkdfGuard.Initializer
hkdfguard-init /path/to/32-byte-key-file --material-identifier 83 --iterations 214 --service-name my-service
```

This reads the 32-byte plaintext file, protects it into a signed key blob using OS-native secure
storage under `my-service`, securely erases and overwrites the original file, and prints the
material identifier/iterations to record for later use:

```
Key protected successfully: /path/to/32-byte-key-file
Record these to load this key later: --material-identifier 83 --iterations 214
```

### 2. Build a `KeyRing`

Manually, via `KeyRingBuilder` - register as many independently-protected key files as needed,
each with its own version number and the material identifier/iterations it was protected with:

```csharp
var ring = new KeyRingBuilder()
    .WithCryptoRecipe(new CryptoRecipeBuilder()
        .WithServiceName("my-service")
        .WithKeyDerivation(new Pbkdf2KeyDerivationFunction(KeyInputStorageFactory.Create("my-service")))
        .WithCipher(new AesGcmCipher())
        .WithHash(new HmacSha256Hash()))
    .WithKeyWrapperFactory(new HkdfKeyWrapperFactory())
    .AddKeyFile(version: 1, path: "/path/to/32-byte-key-file", materialIdentifier: 83, iterations: 214)
    .Build();
```

Or from configuration (e.g. `appsettings.json`) via `HkdfGuard.Options`:

```json
{
  "HkdfGuard": {
    "ServiceName": "my-service",
    "KeyFiles": [
      { "Version": 1, "Path": "/path/to/32-byte-key-file", "MaterialIdentifier": 83, "Iterations": 214 }
    ]
  }
}
```

```csharp
services.AddOptions<HkdfGuardOptions>()
    .Bind(configuration.GetSection("HkdfGuard"))
    .ValidateOnStart();
services.AddSingleton<IValidateOptions<HkdfGuardOptions>, HkdfGuardOptionsValidator>();

var ring = new HkdfGuardKeyRingFactory().Build(configuredOptions);
```

Registering additional key files at higher version numbers (e.g. during a rotation) is all that's
needed to advance `ring.CurrentVersion` - existing ciphertext tagged with older versions continues
to decrypt correctly as long as those keys stay registered.

### 3. Encrypt and decrypt

```csharp
IDataProtector protector = ring.CreateProtector("cookie-auth"); // "cookie-auth" becomes this protector's AAD

string encrypted = protector.Encrypt("secret value".AsSpan());
// e.g. "enc::v1::AbCdEf..."

Span<char> buffer = new char[protector.GetMaxDecryptedLength(encrypted.AsSpan())];
int written = protector.Decrypt(encrypted.AsSpan(), buffer);
string decrypted = new string(buffer[..written]);
```

A value encrypted by one protector name can never be decrypted by a protector created with a
different name, even from the same `KeyRing` - the name is bound in as AAD on every operation.

### Ephemeral, in-memory-only keys

For scenarios that don't need a durable, file-backed key at all:

```csharp
var keySpec = new CryptoRecipeBuilder()
    .WithServiceName("my-service")
    .WithKeyDerivation(new Pbkdf2KeyDerivationFunction(KeyInputStorageFactory.Create("my-service")))
    .WithCipher(new AesGcmCipher())
    .WithHash(new HmacSha256Hash())
    .WithMaterialIdentifier(41)
    .WithIterations(176)
    .Build();

IDataProtectionKey ephemeralKey = new EphemeralDataProtectionKey(
    keySpec, new HkdfKeyWrapperFactory(), new KeyProtectorFactory());
```

The key is generated once, lazily, on first use, protected into an in-memory-only key blob, and
never written to or read from a file. Key derivation still goes through the same OS-native
storage a durable key would use - only the blob itself is ephemeral.

## Extending the crypto registry

`CryptoComponentRegistry` (in `HkdfGuard.Options`) is pre-seeded with this library's built-in
components (`"Pbkdf2"`, `"AesGcm"`, `"HmacSha256"`, `"Hkdf"`), but is mutable: register a new name
to add an option, or re-register an existing name to replace it, without forking the library.

```csharp
var registry = new CryptoComponentRegistry();
registry.RegisterCipher("AesGcm", () => new MyHardenedAesGcmCipher()); // replace a built-in
registry.RegisterCipher("ChaCha20", () => new MyChaCha20Cipher());     // add a new option

var ring = new HkdfGuardKeyRingFactory(registry).Build(options);
```

## Diagnostics

Both `HkdfGuard.Core` (`HkdfDiagnostics`) and `HkdfGuard.DataProtectionKey`
(`DataProtectionDiagnostics`) expose an `ActivitySource` and a shared `EnableSensitiveLogging`
flag. When enabled, operations emit debug events carrying only non-sensitive metadata (lengths,
versions, identifiers) - raw key, plaintext, and ciphertext bytes are never logged, regardless of
this setting.

## Testing

Each library has a corresponding xUnit test project maintained at 100% (or documented,
justified-exception) line and branch coverage, verified via `coverlet`. Tests that exercise real
key derivation use in-memory `IKeyInputStorage` stand-ins so the suite never touches real
OS-native secure storage.
