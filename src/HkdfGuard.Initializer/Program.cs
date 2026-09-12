using System.Security.Cryptography;
using HkdfGuard.Abstractions;
using HkdfGuard.Core.Cryptography;
using HkdfGuard.Core.Primitives;
using HkdfGuard.Core.Utilities;

const string usage = "Usage: HkdfGuard.Initializer <key-file-path> --material-identifier <int> --iterations <int> [--service-name <name>]";

if (args.Length < 1)
{
    Console.Error.WriteLine(usage);
    return 1;
}

var path = args[0];
string? serviceName = null;
int? materialIdentifier = null;
int? iterations = null;

for (var i = 1; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--material-identifier":
            if (i + 1 >= args.Length || !int.TryParse(args[++i], out var parsedMaterialIdentifier) || parsedMaterialIdentifier < 1)
            {
                Console.Error.WriteLine("--material-identifier requires a positive integer value.");
                return 1;
            }
            materialIdentifier = parsedMaterialIdentifier;
            break;

        case "--iterations":
            if (i + 1 >= args.Length || !int.TryParse(args[++i], out var parsedIterations) || parsedIterations < 1)
            {
                Console.Error.WriteLine("--iterations requires a positive integer value.");
                return 1;
            }
            iterations = parsedIterations;
            break;

        case "--service-name":
            if (i + 1 >= args.Length)
            {
                Console.Error.WriteLine("--service-name requires a value.");
                return 1;
            }
            serviceName = args[++i];
            break;

        default:
            Console.Error.WriteLine($"Unrecognized argument: {args[i]}");
            Console.Error.WriteLine(usage);
            return 1;
    }
}

if (materialIdentifier is null || iterations is null)
{
    Console.Error.WriteLine("--material-identifier and --iterations are required.");
    Console.Error.WriteLine(usage);
    return 1;
}

serviceName ??= "HkdfGuard";

// Salt/EncryptedKeySalt/EncryptedKeyValue lengths match KeyProtector's output shape for a
// 32 byte plaintext key: a 32 byte wrapper nonce, followed by AesGcmCipher's own 12 byte nonce,
// 32 byte ciphertext, and 16 byte tag (12 + 32 + 16 = 60).
var blobSpec = new KeyBlobSpec(
    saltLength: 64,
    encryptedKeySaltLength: 32,
    encryptedKeyValueLength: 60,
    signatureLength: 32);

var fileInfo = new FileInfo(path);
if (!fileInfo.Exists)
{
    Console.Error.WriteLine($"Key file not found: {path}");
    return 1;
}

if (fileInfo.Length == blobSpec.TotalLength)
{
    Console.WriteLine("Key is already protected; nothing to do.");
    return 0;
}

if (fileInfo.Length != 32)
{
    Console.Error.WriteLine(
        $"Unexpected key file length {fileInfo.Length}; expected 32 (unprotected) or {blobSpec.TotalLength} (protected).");
    return 1;
}

Span<byte> plaintextKey = stackalloc byte[32];
try
{
    using (var readStream = new FileStream(path, FileMode.Open, FileAccess.Read))
    {
        readStream.ReadExactly(plaintextKey);
    }

    var salt = RandomNumberGenerator.GetBytes(blobSpec.SaltLength);

    var keySpec = DefaultCryptoRecipe.Create(serviceName, materialIdentifier.Value, iterations.Value);
    var protector = DefaultCryptoRecipe.KeyProtectorFactory.Create(keySpec, salt);

    var blob = KeyBlobFactory.Create(plaintextKey, protector, keySpec, blobSpec, salt);

    var blobBytes = new byte[blobSpec.TotalLength];
    blob.Save(blobBytes);

    // Securely erase the plaintext before replacing the file with the protected blob.
    using (var eraseStream = new FileStream(path, FileMode.Open, FileAccess.Write))
    {
        eraseStream.Write(new byte[32]);
        eraseStream.Flush();
    }
    File.Delete(path);

    File.WriteAllBytes(path, blobBytes);

    Console.WriteLine($"Key protected successfully: {path}");
    Console.WriteLine($"Record these to load this key later: --material-identifier {materialIdentifier} --iterations {iterations}");
    return 0;
}
finally
{
    ArrayUtility.ZeroMemory(plaintextKey);
}
