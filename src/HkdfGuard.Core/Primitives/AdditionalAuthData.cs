using System.Text;
using HkdfGuard.Abstractions;

namespace HkdfGuard.Core.Primitives;

public sealed class AdditionalAuthData : IAdditionalAuthData
{
    public static readonly IAdditionalAuthData Empty = new AdditionalAuthData(ReadOnlySpan<byte>.Empty);

    private readonly byte[] _bytes;

    public AdditionalAuthData(ReadOnlySpan<byte> data)
    {
        _bytes = data.IsEmpty ? [] : data.ToArray();
    }

    public AdditionalAuthData(ReadOnlySpan<char> data)
    {
        if (data.IsEmpty)
        {
            _bytes = [];
            return;
        }

        _bytes = new byte[Encoding.UTF8.GetByteCount(data)];
        Encoding.UTF8.GetBytes(data, _bytes);
    }

    /// <inheritdoc/>
    public ReadOnlySpan<byte> AsSpan()
        => _bytes.Length == 0 ? ReadOnlySpan<byte>.Empty : _bytes;
}
