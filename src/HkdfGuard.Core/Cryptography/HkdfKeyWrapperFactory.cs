using HkdfGuard.Abstractions;

namespace HkdfGuard.Core.Cryptography;

public sealed class HkdfKeyWrapperFactory : IKeyWrapperFactory
{
    public IKeyWrapper Create(IKeySpec spec, IKeyBlob blob)
        => new HkdfKeyWrapper(spec.KeyDerivation, spec.Cipher, blob, spec.MaterialIdentifier, spec.Iterations, spec.ServiceName);
}
