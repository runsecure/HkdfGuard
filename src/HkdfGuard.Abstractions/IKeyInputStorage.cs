namespace HkdfGuard.Abstractions;

public interface IKeyInputStorage
{
    public int CreateOrGet(string index, scoped Span<byte> material);
}
