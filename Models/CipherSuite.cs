namespace sslanalyze.Models;

public class CipherSuite
{
    public string Name { get; set; } = string.Empty;
    public string Protocol { get; set; } = string.Empty;
    public string HashAlgorithm { get; set; } = string.Empty;
    public string EncryptionAlgorithm { get; set; } = string.Empty;
    public bool Recommended { get; set; }
    public bool Secure { get; set; }
    public List<string> TLSVersion { get; set; } = new();
}
