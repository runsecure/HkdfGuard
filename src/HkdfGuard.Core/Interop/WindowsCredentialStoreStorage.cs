using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using HkdfGuard.Abstractions;

namespace HkdfGuard.Core.Interop;

public class WindowsCredentialStoreStorage : IKeyInputStorage
{
    private const uint CRED_TYPE_GENERIC = 1;
    private const uint CRED_PERSIST_LOCAL_MACHINE = 2;

    public int CreateOrGet(string index, Span<byte> material)
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
        Span<byte> keyMaterial = stackalloc byte[32];
        RandomNumberGenerator.Fill(keyMaterial);
        // Copy keyMaterial into unmanaged memory
        IntPtr blob = Marshal.AllocHGlobal(32);
        try
        {
            Marshal.Copy(keyMaterial.ToArray(), 0, blob, 32);

            var cred = new CREDENTIAL
            {
                Type = CRED_TYPE_GENERIC,
                TargetName = index,
                CredentialBlobSize = 32,
                CredentialBlob = blob,
                Persist = CRED_PERSIST_LOCAL_MACHINE,
                UserName = ""
            };

            if (!CredWrite(ref cred, 0))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        finally
        {
            Marshal.FreeHGlobal(blob);
        }
    }

    private bool TryLoad(string index, Span<byte> destination)
    {
        if (destination.Length < 32)
            throw new ArgumentException("Destination must be 32 bytes.");

        if (!CredRead(index, CRED_TYPE_GENERIC, 0, out IntPtr credPtr))
            return false;

        try
        {
            var cred = Marshal.PtrToStructure<CREDENTIAL>(credPtr);

            if (cred.CredentialBlobSize != 32)
                return false;

            Marshal.Copy(cred.CredentialBlob, destination.ToArray(), 0, 32);
            return true;
        }
        finally
        {
            CredFree(credPtr);
        }
    }

    // ---------------- Win32 Interop ----------------

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CREDENTIAL
    {
        public uint Flags;
        public uint Type;
        public string TargetName;
        public string Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public uint Persist;
        public uint AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias;
        public string UserName;
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CredWrite(ref CREDENTIAL credential, uint flags);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CredRead(string target, uint type, uint flags, out IntPtr credential);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CredDelete(string target, uint type, uint flags);

    [DllImport("advapi32.dll")]
    private static extern void CredFree(IntPtr buffer);
}
