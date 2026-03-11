using System.Text.Json.Serialization;

namespace sslanalyze.Models;

public partial class CipherSuiteResponse
{
    [JsonPropertyName("ciphersuites")]
    public List<Dictionary<string, Ciphersuite>> CipherSuites { get; set; } = new();
}

public partial class Ciphersuite
{
    [JsonPropertyName("gnutls_name")]
    public string GnutlsName { get; set; } = string.Empty;

    [JsonPropertyName("openssl_name")]
    public string OpensslName { get; set; } = string.Empty;

    [JsonPropertyName("hex_byte_1")]
    public string HexByte1 { get; set; } = string.Empty;

    [JsonPropertyName("hex_byte_2")]
    public string HexByte2 { get; set; } = string.Empty;

    [JsonPropertyName("protocol_version")]
    public string ProtocolVersion { get; set; } = string.Empty;

    [JsonPropertyName("kex_algorithm")]
    public string KexAlgorithm { get; set; } = string.Empty;

    [JsonPropertyName("auth_algorithm")]
    public string AuthAlgorithm { get; set; } = string.Empty;

    [JsonPropertyName("enc_algorithm")]
    public string EncAlgorithm { get; set; } = string.Empty;

    [JsonPropertyName("hash_algorithm")]
    public string HashAlgorithm { get; set; } = string.Empty;

    [JsonPropertyName("security")]
    public string Security { get; set; } = string.Empty;

    [JsonPropertyName("tls_version")]
    public List<string> TlsVersion { get; set; } = new();
}
