using System.Security.Cryptography;
using HkdfGuard.Abstractions;
using HkdfGuard.Core.Cryptography;
using HkdfGuard.Core.Primitives;
using HkdfGuard.Core.Utilities;

namespace HkdfGuard.Initializer;

/// <summary>
/// The hkdfguard-init CLI's actual argument-parsing and execution logic, pulled out of
/// Program.cs's top-level statements so it can be exercised directly by tests - output goes
/// through the given TextWriters rather than straight to Console, and createKeySpec defaults to
/// DefaultCryptoRecipe.Create (real OS-native secure storage) but can be swapped for a test
/// double backed by an in-memory IKeyInputStorage.
/// </summary>
public static class InitializerApp
{
    public const string Usage = """
        Usage: HkdfGuard.Initializer <key-file-path> --material-identifier|-mi <int> --iterations|-i <int> [--service-name|-sn <name>] [--dek|-d <base64>]
        """;

    public static int Run(
        string[] args,
        TextWriter output,
        TextWriter error,
        Func<string, int, int, IKeySpec>? createKeySpec = null)
    {
        createKeySpec ??= DefaultCryptoRecipe.Create;

        if (args.Length < 1)
        {
            error.WriteLine(Usage);
            return 1;
        }

        var path = args[0];
        string? serviceName = null;
        int? materialIdentifier = null;
        int? iterations = null;
        string? dekBase64 = null;

        for (var i = 1; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--material-identifier":
                case "-mi":
                    if (i + 1 >= args.Length || !int.TryParse(args[++i], out var parsedMaterialIdentifier) || parsedMaterialIdentifier < 1)
                    {
                        error.WriteLine("--material-identifier requires a positive integer value.");
                        return 1;
                    }
                    materialIdentifier = parsedMaterialIdentifier;
                    break;

                case "--iterations":
                case "-i":
                    if (i + 1 >= args.Length || !int.TryParse(args[++i], out var parsedIterations) || parsedIterations < 1)
                    {
                        error.WriteLine("--iterations requires a positive integer value.");
                        return 1;
                    }
                    iterations = parsedIterations;
                    break;

                case "--service-name":
                case "-sn":
                    if (i + 1 >= args.Length)
                    {
                        error.WriteLine("--service-name requires a value.");
                        return 1;
                    }
                    serviceName = args[++i];
                    break;

                case "--dek":
                case "-d":
                    if (i + 1 >= args.Length)
                    {
                        error.WriteLine("--dek requires a base64-encoded 32 byte value.");
                        return 1;
                    }
                    dekBase64 = args[++i];
                    break;

                default:
                    error.WriteLine($"Unrecognized argument: {args[i]}");
                    error.WriteLine(Usage);
                    return 1;
            }
        }

        if (materialIdentifier is null || iterations is null)
        {
            error.WriteLine("--material-identifier and --iterations are required.");
            error.WriteLine(Usage);
            return 1;
        }

        serviceName ??= "HkdfGuard";

        Span<byte> plaintextKey = stackalloc byte[32];
        try
        {
            if (dekBase64 is not null)
            {
                if (!Convert.TryFromBase64String(dekBase64, plaintextKey, out var bytesWritten) || bytesWritten != 32)
                {
                    error.WriteLine("--dek must be a base64-encoded 32 byte value.");
                    return 1;
                }
            }

            // Salt/EncryptedKeySalt/EncryptedKeyValue lengths match KeyProtector's output shape for a
            // 32 byte plaintext key: a 32 byte wrapper nonce, followed by AesGcmCipher's own 12 byte nonce,
            // 32 byte ciphertext, and 16 byte tag (12 + 32 + 16 = 60).
            var blobSpec = new KeyBlobSpec(
                saltLength: 64,
                encryptedKeySaltLength: 32,
                encryptedKeyValueLength: 60,
                signatureLength: 64);

            // When a Dek is supplied on the command line, path is a fresh destination - refuse to
            // clobber whatever's already there rather than guessing whether it's safe to overwrite.
            // Without one, path is read in place: an existing unprotected 32 byte key file that this
            // run protects, or an already-protected file that's left untouched.
            var readPlaintextFromDestination = dekBase64 is null;
            if (readPlaintextFromDestination && File.Exists(path))
            {
                var fileInfo = new FileInfo(path);
                if (fileInfo.Length == blobSpec.TotalLength)
                {
                    output.WriteLine("Key is already protected; nothing to do.");
                    return 0;
                }

                if (fileInfo.Length != 32)
                {
                    error.WriteLine(
                        $"Unexpected key file length {fileInfo.Length}; expected 32 (unprotected) or {blobSpec.TotalLength} (protected).");
                    return 1;
                }
            }
            else if (readPlaintextFromDestination)
            {
                error.WriteLine($"Key file not found: {path}");
                return 1;
            }
            else if (File.Exists(path))
            {
                error.WriteLine($"Destination file already exists, refusing to overwrite: {path}");
                return 1;
            }

            if (readPlaintextFromDestination)
            {
                using var readStream = new FileStream(path, FileMode.Open, FileAccess.Read);
                readStream.ReadExactly(plaintextKey);
            }

            var salt = RandomNumberGenerator.GetBytes(blobSpec.SaltLength);

            var keySpec = createKeySpec(serviceName, materialIdentifier.Value, iterations.Value);
            var protector = new KeyProtector(keySpec, salt);

            var blob = KeyBlobFactory.Create(plaintextKey, protector, keySpec, blobSpec, salt);

            var blobBytes = new byte[blobSpec.TotalLength];
            blob.Save(blobBytes);

            if (readPlaintextFromDestination)
            {
                // Securely erase the plaintext before replacing the file with the protected blob.
                using (var eraseStream = new FileStream(path, FileMode.Open, FileAccess.Write))
                {
                    eraseStream.Write(new byte[32]);
                    eraseStream.Flush();
                }
                File.Delete(path);
            }

            File.WriteAllBytes(path, blobBytes);

            output.WriteLine($"Key protected successfully: {path}");
            output.WriteLine($"Record these to load this key later: --material-identifier {materialIdentifier} --iterations {iterations}");
            return 0;
        }
        finally
        {
            ArrayUtility.ZeroMemory(plaintextKey);
        }
    }
}
