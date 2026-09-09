using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using HkdfGuard.Abstractions;

namespace HkdfGuard.Core.Interop;

internal class LinuxSystemdStorage(string credsDir = "") : IKeyInputStorage
{
    private const uint KEYCTL_SEARCH = 10;
    private const uint KEYCTL_UNLINK = 9;

    private readonly int _targetKeyring;
    private readonly string _prefix;
    
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
        RandomNumberGenerator.Fill(keyMaterial);
        StoreToKeyRing(index, keyMaterial);
    }
    
    private void StoreToKeyRing(string index, ReadOnlySpan<byte> keyMaterial)
    {
        if (keyMaterial.Length != 32)
            throw new ArgumentException("Key material must be 32 bytes.");

        var keyId = add_key("user", index, keyMaterial.ToArray(), keyMaterial.Length, _targetKeyring);
        if (keyId < 0)
            throw new Exception($"add_key failed: {Marshal.GetLastWin32Error()}");

        LinuxKeyRingTracker.AddOrUpdate(index, keyId);
    }
    
    private bool TryLoadFromKeyRing(int index, Span<byte> destination)
    {
        if (destination.Length < 32)
            throw new ArgumentException("Destination must be 32 bytes.");

        var name = $"{_prefix}{index}";

        var keyId = keyctl(KEYCTL_SEARCH, _targetKeyring, name, 0);
        if (keyId < 0)
            return false;

        var size = keyctl_read(keyId, null, 0);
        if (size != 32)
            return false;

        Span<byte> buffer = stackalloc byte[32];
        var read = keyctl_read(keyId, buffer, 32);
        if (read != 32)
            return false;

        buffer.CopyTo(destination);
        return true;
    }

    public bool TryLoad(string index, Span<byte> destination)
    {
        if (LinuxKeyRingTracker.TryGetValue(index, out var keyIndex)
            && TryLoadFromKeyRing(keyIndex, destination))
            return true;

        if (TryReadViaPipe(index, destination))
        {
            StoreToKeyRing(index, destination);
        }
        
        if (LinuxKeyRingTracker.TryGetValue(index, out keyIndex)
            && TryLoadFromKeyRing(keyIndex, destination))
            return true;

        return false;
    }
    
    public bool TryReadViaPipe(string index, Span<byte> destination)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "systemd-creds",
            ArgumentList = { "decrypt", $"{index}.creds" },
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };

        using var proc = Process.Start(psi);
        using var stdout = proc.StandardOutput.BaseStream;

        var read = stdout.Read(destination);
        proc.WaitForExit();

        return read == destination.Length && proc.ExitCode == 0;
    }
    
    /// <summary>
    /// Write a new TPM-backed encrypted credential using systemd-creds.
    /// </summary>
    public void WriteEncrypted(string index)
    {
        // Write plaintext to a temp file (stack-only buffer cannot be passed to systemd-creds)
        var tmpPath = Path.GetTempFileName();

        try
        {
            // Write plaintext to disk ONLY temporarily
            File.WriteAllBytes(tmpPath, RandomNumberGenerator.GetBytes(32));

            // systemd-creds encrypt --with-key=tpm2 <tmp> <output>
            var psi = new ProcessStartInfo
            {
                FileName = "systemd-creds",
                ArgumentList = { "encrypt", "--with-key=tpm2", "--name", index, tmpPath, $"{index}.creds" },
                RedirectStandardError = true,
                RedirectStandardOutput = true
            };

            using var proc = Process.Start(psi);
            proc.WaitForExit();

            if (proc.ExitCode != 0)
                throw new Exception($"systemd-creds failed: {proc.StandardError.ReadToEnd()}");
        }
        finally
        {
            // Zero and delete temp file
            try
            {
                var zero = new byte[32];
                File.WriteAllBytes(tmpPath, zero);
                File.Delete(tmpPath);
            }
            catch { /* best effort */ }
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

    [DllImport("libkeyutils.so.1", SetLastError = true)]
    private static extern int add_key(
        string type,
        string description,
        byte[] payload,
        int plen,
        int keyring);

    [DllImport("libkeyutils.so.1", SetLastError = true)]
    private static extern int keyctl(
        uint cmd,
        int arg2,
        string arg3,
        int arg4);

    [DllImport("libkeyutils.so.1", SetLastError = true)]
    private static extern int keyctl_read(
        int key,
        Span<byte> buffer,
        int buflen);
}