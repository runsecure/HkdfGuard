using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using HkdfGuard.Abstractions;
using HkdfGuard.Core.Utilities;

namespace HkdfGuard.Core.Interop;

internal class LinuxSystemdStorage(string credsDir = "/run/credentials") : IKeyInputStorage
{
    // The process keyring dies with the process that created it, which defeats the point of
    // durable key-material storage (every fresh invocation would regenerate it). The user
    // keyring is scoped to the UID instead, so it survives across separate process runs the
    // same way a macOS Keychain or Windows Credential Manager entry does.
    private const int KEY_SPEC_USER_KEYRING = -4;
        
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
        if (IsSystemdCredsSupported())
        {
            WriteEncrypted(index);
            return;
        }
        Span<byte> keyMaterial = stackalloc byte[32];
        try
        {
            RandomNumberGenerator.Fill(keyMaterial);
            StoreToKeyRing(index, keyMaterial);
        }
        finally
        {
            ArrayUtility.ZeroMemory(keyMaterial);
        }
    }
    
    private void StoreToKeyRing(string index, ReadOnlySpan<byte> keyMaterial)
    {
        if (keyMaterial.Length != 32)
            throw new ArgumentException("Key material must be 32 bytes.");

        // Pin the span and call add_key with a pointer-based overload
        unsafe
        {
            fixed (byte* p = keyMaterial)
            {
                var keyId = add_key_span("user", index, p, keyMaterial.Length, KEY_SPEC_USER_KEYRING);
                if (keyId < 0)
                    throw new Exception($"add_key failed: {Marshal.GetLastWin32Error()}");

                LinuxKeyRingTracker.AddOrUpdate(index, keyId);
            }
        }
    }
    
    private bool TryLoadFromKeyRing(int keyId, Span<byte> destination)
    {
        if (destination.Length < 32)
            throw new ArgumentException("Destination must be 32 bytes.");

        unsafe
        {
            fixed (byte* p = destination)
            {
                var read = keyctl_read(keyId, p, destination.Length);
                if (read != 32)
                    return false;
            }
        }
        return true;
    }

    private bool TryLoad(string index, Span<byte> destination)
    {
        if (LinuxKeyRingTracker.TryGetValue(index, out var keyIndex)
            && TryLoadFromKeyRing(keyIndex, destination))
            return true;

        // Gated the same way Generate gates WriteEncrypted - a container never has a real
        // systemd managing /run/credentials, so this must never shell out to systemd-creds
        // there (it wouldn't just fail, TryReadViaPipe would throw since the binary itself is
        // absent) and instead relies on the kernel keyring alone.
        if (IsSystemdCredsSupported() && TryReadViaPipe(index, destination))
        {
            StoreToKeyRing(index, destination);
        }

        if (LinuxKeyRingTracker.TryGetValue(index, out keyIndex)
            && TryLoadFromKeyRing(keyIndex, destination))
            return true;

        return false;
    }

    private bool TryReadViaPipe(string index, Span<byte> destination)
    {
        var credsPath = Path.Combine(credsDir, $"{index}.creds");
        var psi = new ProcessStartInfo
        {
            FileName = "systemd-creds",
            ArgumentList = { "decrypt", credsPath },
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };

        using var proc = Process.Start(psi);
        using var stdout = proc.StandardOutput.BaseStream;

        int total = 0;
        while (total < destination.Length)
        {
            int read = stdout.Read(destination.Slice(total));
            if (read <= 0)
                break;
            total += read;
        }

        proc.WaitForExit();

        return total == destination.Length && proc.ExitCode == 0;
    }
    
    /// <summary>
    /// Write a new TPM-backed encrypted credential using systemd-creds.
    /// </summary>
    private void WriteEncrypted(string index)
    {
        // 1. Generate 32-byte DEK in stack memory
        Span<byte> dek = stackalloc byte[32];
        RandomNumberGenerator.Fill(dek);

        // 2. Create anonymous RAM-backed file (never hits disk)
        int fd = memfd_create("hkdfguard-dek", MFD_CLOEXEC);
        if (fd < 0)
            throw new Exception("memfd_create failed");

        // 4. Create a temporary mount point (RAM-only)
        string mountPath = $"/run/hkdfguard-{Guid.NewGuid():N}";
        Directory.CreateDirectory(mountPath);
        
        string materialPath = Path.Combine(mountPath, "material");
        File.Create(materialPath).Dispose(); 
        
        var credsPath = Path.Combine(credsDir, $"{index}.creds");
        
        try
        {
            // 3. Write DEK directly into memfd
            unsafe
            {
                fixed (byte* p = dek)
                {
                    if (write(fd, p, 32) != 32)
                        throw new Exception("write() failed");
                }
            }

            // 5. Bind-mount memfd into a visible path for systemd-creds
            //    This exposes the file ONLY to systemd-creds, not the filesystem.
            if (mount_fd(fd, materialPath) != 0)
                throw new Exception("mount_fd failed");

            // 6. Run systemd-creds encrypt
            var psi = new ProcessStartInfo
            {
                FileName = "systemd-creds",
                ArgumentList = { "encrypt", "--with-key=tpm2", "--name", index, materialPath, credsPath },
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                UseShellExecute = false
            };

            using var proc = Process.Start(psi);
            proc.WaitForExit();

            if (proc.ExitCode != 0)
                throw new Exception($"systemd-creds failed: {proc.StandardError.ReadToEnd()}");
        }
        finally
        {
            // 7. Zeroize DEK stack buffer
            ArrayUtility.ZeroMemory(dek);

            // 8. Cleanup mount + memfd
            try
            {
                umount(mountPath);
            }
            catch
            {
                //Do nothing
            }

            try
            {
                Directory.Delete(mountPath);

            }
            catch
            {
                //Do nothing
            }
            close(fd);
        }
    }
    
    private bool IsSystemdCredsSupported()
    {
        // 1. Are we under systemd with a credentials directory?
        if (string.IsNullOrEmpty(credsDir) || !Directory.Exists(credsDir))
            return false;

        // 2. Does systemd-creds exist in PATH?
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "systemd-creds",
                ArgumentList = { "--version" },
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            using var proc = Process.Start(psi);
            proc.WaitForExit();

            return proc.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }
    
    // ---------------- Native Linux Keyring API ----------------

    [DllImport("libkeyutils.so.1", SetLastError = true, EntryPoint = "add_key")]
    private static extern unsafe int add_key_span(
        string type,
        string description,
        byte* payload,
        int plen,
        int keyring);

    [DllImport("libkeyutils.so.1", SetLastError = true, EntryPoint = "keyctl_read")]
    private static extern unsafe int keyctl_read(
        int key,
        byte* buffer,
        int buflen);
    
    private const int MFD_CLOEXEC = 0x0001;

    [DllImport("libc", SetLastError = true)]
    private static extern int memfd_create(string name, uint flags);

    [DllImport("libc", SetLastError = true)]
    private static unsafe extern int write(int fd, void* buf, int count);

    [DllImport("libc", SetLastError = true)]
    private static extern int close(int fd);

    [DllImport("libc", SetLastError = true)]
    private static extern int mount(string source, string target, string fstype, ulong flags, string data);

    [DllImport("libc", SetLastError = true)]
    private static extern int umount(string target);

    // Bind-mount the memfd into a path
    private static int mount_fd(int fd, string target)
    {
        string source = $"/proc/self/fd/{fd}";
        return mount(source, target, null, 4096 /* MS_BIND */, null);
    }
}