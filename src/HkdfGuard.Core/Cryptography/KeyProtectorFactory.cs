using HkdfGuard.Abstractions;

namespace HkdfGuard.Core.Cryptography;

public sealed class KeyProtectorFactory : IKeyProtectorFactory
{
    public IKeyProtector Create(IKeySpec spec, byte[] salt)
        => new KeyProtector(spec.KeyDerivation, spec.Cipher, salt, spec.MaterialIdentifier, spec.Iterations, spec.ServiceName);
}
