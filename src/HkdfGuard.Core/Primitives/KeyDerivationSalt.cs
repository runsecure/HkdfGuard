using System.Text;
using HkdfGuard.Core.Utilities;
using HkdfGuard.Abstractions;

namespace HkdfGuard.Core.Primitives;

public sealed class KeyDerivationSalt : IKeyDerivationSalt
{
    private readonly byte[] _bytes;

    public KeyDerivationSalt(ReadOnlySpan<byte> salt)
        : this(salt, ReadOnlySpan<byte>.Empty)
    {
    }

    public KeyDerivationSalt(ReadOnlySpan<byte> salt, ReadOnlySpan<byte> info)
    {
        ValidateSalt(salt);

        _bytes = new byte[salt.Length + info.Length];
        salt.CopyTo(_bytes);
        info.CopyTo(_bytes.AsSpan(salt.Length));
    }

    public KeyDerivationSalt(ReadOnlySpan<byte> salt, ReadOnlySpan<char> info)
    {
        ValidateSalt(salt);

        var infoByteCount = Encoding.UTF8.GetByteCount(info);
        _bytes = new byte[salt.Length + infoByteCount];
        salt.CopyTo(_bytes);
        Encoding.UTF8.GetBytes(info, _bytes.AsSpan(salt.Length));
    }

    private static void ValidateSalt(ReadOnlySpan<byte> salt)
    {
        if (ArrayUtility.IsNullOrEmpty(salt))
            throw new ArgumentException("Salt must not be empty or all zero.", nameof(salt));

        if (salt.Length % 32 != 0)
            throw new ArgumentException("Salt length must be a multiple of 32 bytes.", nameof(salt));
    }

    public ReadOnlySpan<byte> AsSpan() => _bytes;
}
