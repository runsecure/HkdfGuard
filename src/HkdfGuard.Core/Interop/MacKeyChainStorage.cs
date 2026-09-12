using System.Runtime.InteropServices;
using System.Security.Cryptography;
using HkdfGuard.Abstractions;
using HkdfGuard.Core.Utilities;

namespace HkdfGuard.Core.Interop;

internal class MacKeyChainStorage(string service) : IKeyInputStorage
{
    private const string SecurityFramework = "/System/Library/Frameworks/Security.framework/Security";
    private const string CoreFoundation = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";

    // CFDictionaryCreate needs the standard CFType key/value callback structs (not NULL) so that
    // consumers like Security framework can look up well-known keys (kSecClass, etc.) by value
    // instead of raw pointer identity, and so the dictionary properly retains/releases its contents.
    // These are exported as data symbols (not functions), so they're loaded via NativeLibrary.GetExport
    // rather than a plain DllImport.
    private static readonly IntPtr KeyCallbacks;
    private static readonly IntPtr ValueCallbacks;

    // kCFBooleanTrue is itself declared as a CFBooleanRef (a pointer), so the exported symbol's
    // address holds the pointer value rather than being the value itself - one extra dereference
    // versus the callback structs above, which are read directly by address.
    private static readonly IntPtr KCFBooleanTrue;

    static MacKeyChainStorage()
    {
        var coreFoundation = NativeLibrary.Load(CoreFoundation);
        KeyCallbacks = NativeLibrary.GetExport(coreFoundation, "kCFTypeDictionaryKeyCallBacks");
        ValueCallbacks = NativeLibrary.GetExport(coreFoundation, "kCFTypeDictionaryValueCallBacks");
        KCFBooleanTrue = Marshal.ReadIntPtr(NativeLibrary.GetExport(coreFoundation, "kCFBooleanTrue"));
    }

    public int CreateOrGet(string index, scoped Span<byte> material)
    {
        if(TryLoad(index, material))
            return material.Length;
        Generate(index);
        if(TryLoad(index, material))
            return material.Length;
        return 0;
    }

    private void Generate(string index)
    {
        if (string.IsNullOrEmpty(index))
            throw new ArgumentNullException(nameof(index));

        Span<byte> keyMaterial = stackalloc byte[32];
        try
        {
            RandomNumberGenerator.Fill(keyMaterial);
            using var dict = BuildAddDictionary(service, index, keyMaterial);

            int status = SecItemAdd(dict.Handle, out _);
            if (status != 0)
                throw new Exception($"SecItemAdd failed: {status}");
        }
        finally
        {
            ArrayUtility.ZeroMemory(keyMaterial);
        }
    }

    private bool TryLoad(string index, scoped Span<byte> destination)
    {
        if (destination.Length != 32)
            throw new ArgumentException("Destination must be 32 bytes.");

        using var query = BuildQueryDictionary(service, index);

        int status = SecItemCopyMatching(query.Handle, out IntPtr result);
        if (status != 0 || result == IntPtr.Zero)
            return false;

        try
        {
            ReadCFData(result, destination);
            return true;
        }
        finally
        {
            CFRelease(result);
        }
    }

    public void Delete(string index)
    {
        using var query = BuildDeleteDictionary(service, index);

        SecItemDelete(query.Handle);
    }

    public void Dispose()
    {
        // Nothing persistent to dispose; CF objects are wrapped individually.
    }

    // ---------------- CF Helpers ----------------

    private static CFDictionary BuildAddDictionary(string service, string account, ReadOnlySpan<byte> data)
    {
        IntPtr cfService = CFStringCreate(service);
        IntPtr cfAccount = CFStringCreate(account);
        IntPtr cfData = CFDataCreate(data);

        IntPtr[] keys =
        {
            Sec.kSecClass,
            Sec.kSecAttrService,
            Sec.kSecAttrAccount,
            Sec.kSecValueData
        };

        IntPtr[] values =
        {
            Sec.kSecClassGenericPassword,
            cfService,
            cfAccount,
            cfData
        };

        return new CFDictionary(keys, values, [cfService, cfAccount, cfData]);
    }

    private static CFDictionary BuildQueryDictionary(string service, string account)
    {
        IntPtr cfService = CFStringCreate(service);
        IntPtr cfAccount = CFStringCreate(account);

        IntPtr[] keys =
        {
            Sec.kSecClass,
            Sec.kSecAttrService,
            Sec.kSecAttrAccount,
            Sec.kSecReturnData
        };

        IntPtr[] values =
        {
            Sec.kSecClassGenericPassword,
            cfService,
            cfAccount,
            KCFBooleanTrue
        };

        return new CFDictionary(keys, values, [cfService, cfAccount]);
    }

    private static CFDictionary BuildDeleteDictionary(string service, string account)
    {
        IntPtr cfService = CFStringCreate(service);
        IntPtr cfAccount = CFStringCreate(account);

        IntPtr[] keys =
        {
            Sec.kSecClass,
            Sec.kSecAttrService,
            Sec.kSecAttrAccount
        };

        IntPtr[] values =
        {
            Sec.kSecClassGenericPassword,
            cfService,
            cfAccount
        };

        return new CFDictionary(keys, values, [cfService, cfAccount]);
    }

    private static void ReadCFData(IntPtr cfData, Span<byte> dest)
    {
        nint len = CFDataGetLength(cfData);
        if (len != 32)
            throw new Exception("Keychain item is not 32 bytes.");

        IntPtr ptr = CFDataGetBytePtr(cfData);

        unsafe
        {
            fixed (byte* destPtr = dest)
            {
                Buffer.MemoryCopy(
                    source: (void*)ptr,
                    destination: destPtr,
                    destinationSizeInBytes: dest.Length,
                    sourceBytesToCopy: 32);
            }
        }
    }

    // ---------------- Native Imports ----------------

    [DllImport(SecurityFramework)]
    private static extern int SecItemAdd(IntPtr attributes, out IntPtr result);

    [DllImport(SecurityFramework)]
    private static extern int SecItemCopyMatching(IntPtr query, out IntPtr result);

    [DllImport(SecurityFramework)]
    private static extern int SecItemDelete(IntPtr query);

    [DllImport(CoreFoundation)]
    private static extern void CFRelease(IntPtr cfRef);

    [DllImport(CoreFoundation)]
    private static extern IntPtr CFStringCreateWithCString(IntPtr alloc, string str, uint encoding);

    [DllImport(CoreFoundation)]
    private static extern IntPtr CFDataCreate(IntPtr allocator, byte[] bytes, int length);

    [DllImport(CoreFoundation)]
    private static extern nint CFDataGetLength(IntPtr cfData);

    [DllImport(CoreFoundation)]
    private static extern IntPtr CFDataGetBytePtr(IntPtr cfData);

    private static IntPtr CFStringCreate(string s)
        => CFStringCreateWithCString(IntPtr.Zero, s, 0x08000100);

    private static IntPtr CFDataCreate(ReadOnlySpan<byte> data)
        => CFDataCreate(IntPtr.Zero, data.ToArray(), data.Length);

    // ---------------- CFDictionary Wrapper ----------------

    // CFDictionaryCreate is called with NULL key/value callbacks, so the dictionary does not retain
    // its contents - the caller must keep them alive for as long as the dictionary is used, then
    // release them. Only the CFType values created specifically for this dictionary (ownedValues)
    // are released on Dispose; shared/static values (e.g. the Sec.* constants) must never be passed
    // there, since they are meant to live for the process's lifetime.
    private sealed class CFDictionary : IDisposable
    {
        public IntPtr Handle { get; }
        private readonly IntPtr[] _ownedValues;

        [DllImport(CoreFoundation)]
        private static extern IntPtr CFDictionaryCreate(
            IntPtr allocator,
            IntPtr[] keys,
            IntPtr[] values,
            nint count,
            IntPtr keyCallbacks,
            IntPtr valueCallbacks);

        public CFDictionary(IntPtr[] keys, IntPtr[] values, IntPtr[] ownedValues)
        {
            Handle = CFDictionaryCreate(
                IntPtr.Zero,
                keys,
                values,
                keys.Length,
                KeyCallbacks,
                ValueCallbacks);

            _ownedValues = ownedValues;
        }

        public void Dispose()
        {
            if (Handle != IntPtr.Zero)
                CFRelease(Handle);

            foreach (var v in _ownedValues)
                CFRelease(v);
        }
    }

    private static class Sec
    {
        public static readonly IntPtr kSecClass = CFStringCreate("class");
        public static readonly IntPtr kSecClassGenericPassword = CFStringCreate("genp");
        public static readonly IntPtr kSecAttrService = CFStringCreate("svce"); public static readonly IntPtr kSecAttrAccount = CFStringCreate("acct");
        public static readonly IntPtr kSecValueData = CFStringCreate("v_Data");
        public static readonly IntPtr kSecReturnData = CFStringCreate("r_Data");
    }

}
