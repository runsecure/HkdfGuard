namespace HkdfGuard.Abstractions;

public class KeyTrackingValue
{
    public int KeyVersion { get; set; }
    public byte[] Value { get; set; }
}
