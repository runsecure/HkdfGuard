using System.Security.Cryptography;

namespace HkdfGuard.Core.Utilities;

public static class ArrayUtility
{
    public static bool IsNullOrEmpty(ReadOnlySpan<byte> input)
    {
        foreach (var b in input)
        {
            if (b != 0)
                return false;
        }
        return true;
    }
    
    public static bool IsNullOrEmpty(ReadOnlySpan<char> input)
    {
        foreach (var b in input)
        {
            if (b != 0)
                return false;
        }
        return true;
    }

    public static void ZeroMemory(Span<byte> input)
    {
        for (var i = 0; i < input.Length; i++)
        {
            input[i] = 0;
        }
        input.Clear();
    }
    
    public static void ZeroMemory(Span<char> input)
    {
        for (var i = 0; i < input.Length; i++)
        {
            input[i] = '\0';
        }
        input.Clear();
    }
}