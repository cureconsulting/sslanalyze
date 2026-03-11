using System.Text.Json.Serialization;

namespace sslanalyze.Models;

public class SSLyzeResponse
{
    [JsonPropertyName("date_scans_completed")]
    public DateTime DateScansCompleted { get; set; }

    [JsonPropertyName("date_scans_started")]
    public DateTime DateScansStarted { get; set; }

    [JsonPropertyName("invalid_server_strings")]
    public List<object> InvalidServerStrings { get; set; } = new();

    [JsonPropertyName("server_scan_results")]
    public List<ServerScanResult> ServerScanResults { get; set; } = new();

    [JsonPropertyName("sslyze_url")]
    public string SslyzeUrl { get; set; } = string.Empty;

    [JsonPropertyName("sslyze_version")]
    public string SslyzeVersion { get; set; } = string.Empty;
}

public class AcceptedCipherSuite
{
    [JsonPropertyName("cipher_suite")]
    public SslyzeCipherSuite CipherSuite { get; set; } = new();

    [JsonPropertyName("ephemeral_key")]
    public EphemeralKey? EphemeralKey { get; set; }
}

public class Attribute
{
    [JsonPropertyName("oid")]
    public Oid Oid { get; set; } = new();

    [JsonPropertyName("rfc4514_string")]
    public string Rfc4514String { get; set; } = string.Empty;

    [JsonPropertyName("value")]
    public string Value { get; set; } = string.Empty;
}

public class CertificateDeployment
{
    [JsonPropertyName("leaf_certificate_has_must_staple_extension")]
    public bool LeafCertificateHasMustStapleExtension { get; set; }

    [JsonPropertyName("leaf_certificate_is_ev")]
    public bool LeafCertificateIsEv { get; set; }

    [JsonPropertyName("leaf_certificate_signed_certificate_timestamps_count")]
    public int LeafCertificateSignedCertificateTimestampsCount { get; set; }

    [JsonPropertyName("leaf_certificate_subject_matches_hostname")]
    public bool LeafCertificateSubjectMatchesHostname { get; set; }

    [JsonPropertyName("ocsp_response")]
    public OcspResponse? OcspResponse { get; set; }

    [JsonPropertyName("ocsp_response_is_trusted")]
    public bool? OcspResponseIsTrusted { get; set; }

    [JsonPropertyName("path_validation_results")]
    public List<PathValidationResult> PathValidationResults { get; set; } = new();

    [JsonPropertyName("received_certificate_chain")]
    public List<ReceivedCertificateChain> ReceivedCertificateChain { get; set; } = new();

    [JsonPropertyName("received_chain_contains_anchor_certificate")]
    public bool ReceivedChainContainsAnchorCertificate { get; set; }

    [JsonPropertyName("received_chain_has_valid_order")]
    public bool ReceivedChainHasValidOrder { get; set; }

    [JsonPropertyName("verified_certificate_chain")]
    public List<VerifiedCertificateChain> VerifiedCertificateChain { get; set; } = new();

    [JsonPropertyName("verified_chain_has_legacy_symantec_anchor")]
    public bool VerifiedChainHasLegacySymantecAnchor { get; set; }

    [JsonPropertyName("verified_chain_has_sha1_signature")]
    public bool VerifiedChainHasSha1Signature { get; set; }
}

public class CertificateInfo
{
    [JsonPropertyName("error_reason")]
    public object? ErrorReason { get; set; }

    [JsonPropertyName("error_trace")]
    public object? ErrorTrace { get; set; }

    [JsonPropertyName("result")]
    public Result? Result { get; set; }

    [JsonPropertyName("status")]
    public string Status { get; set; } = string.Empty;
}

public class SslyzeCipherSuite
{
    [JsonPropertyName("is_anonymous")]
    public bool IsAnonymous { get; set; }

    [JsonPropertyName("key_size")]
    public int KeySize { get; set; }

    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("openssl_name")]
    public string OpensslName { get; set; } = string.Empty;
}

public class ConnectivityResult
{
    [JsonPropertyName("cipher_suite_supported")]
    public string CipherSuiteSupported { get; set; } = string.Empty;

    [JsonPropertyName("client_auth_requirement")]
    public string ClientAuthRequirement { get; set; } = string.Empty;

    [JsonPropertyName("highest_tls_version_supported")]
    public string HighestTlsVersionSupported { get; set; } = string.Empty;

    [JsonPropertyName("supports_ecdh_key_exchange")]
    public bool SupportsEcdhKeyExchange { get; set; }
}

public class EllipticCurves
{
    [JsonPropertyName("error_reason")]
    public object? ErrorReason { get; set; }

    [JsonPropertyName("error_trace")]
    public object? ErrorTrace { get; set; }

    [JsonPropertyName("result")]
    public Result? Result { get; set; }

    [JsonPropertyName("status")]
    public string Status { get; set; } = string.Empty;
}

public class EphemeralKey
{
    [JsonPropertyName("curve_name")]
    public string CurveName { get; set; } = string.Empty;

    [JsonPropertyName("generator")]
    public string Generator { get; set; } = string.Empty;

    [JsonPropertyName("prime")]
    public string Prime { get; set; } = string.Empty;

    [JsonPropertyName("public_bytes")]
    public string PublicBytes { get; set; } = string.Empty;

    [JsonPropertyName("size")]
    public int Size { get; set; }

    [JsonPropertyName("type_name")]
    public string TypeName { get; set; } = string.Empty;

    [JsonPropertyName("x")]
    public string X { get; set; } = string.Empty;

    [JsonPropertyName("y")]
    public string Y { get; set; } = string.Empty;
}

public class EvOid
{
    [JsonPropertyName("dotted_string")]
    public string DottedString { get; set; } = string.Empty;

    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;
}

public class Heartbleed
{
    [JsonPropertyName("error_reason")]
    public object? ErrorReason { get; set; }

    [JsonPropertyName("error_trace")]
    public object? ErrorTrace { get; set; }

    [JsonPropertyName("result")]
    public Result? Result { get; set; }

    [JsonPropertyName("status")]
    public string Status { get; set; } = string.Empty;
}

public class HttpHeaders
{
    [JsonPropertyName("error_reason")]
    public object? ErrorReason { get; set; }

    [JsonPropertyName("error_trace")]
    public object? ErrorTrace { get; set; }

    [JsonPropertyName("result")]
    public object? Result { get; set; }

    [JsonPropertyName("status")]
    public string Status { get; set; } = string.Empty;
}

public class Issuer
{
    [JsonPropertyName("attributes")]
    public List<Attribute> Attributes { get; set; } = new();

    [JsonPropertyName("rfc4514_string")]
    public string Rfc4514String { get; set; } = string.Empty;
}

public class NetworkConfiguration
{
    [JsonPropertyName("network_max_retries")]
    public int NetworkMaxRetries { get; set; }

    [JsonPropertyName("network_timeout")]
    public int NetworkTimeout { get; set; }

    [JsonPropertyName("tls_client_auth_credentials")]
    public object? TlsClientAuthCredentials { get; set; }

    [JsonPropertyName("tls_opportunistic_encryption")]
    public object? TlsOpportunisticEncryption { get; set; }

    [JsonPropertyName("tls_server_name_indication")]
    public string TlsServerNameIndication { get; set; } = string.Empty;

    [JsonPropertyName("xmpp_to_hostname")]
    public object? XmppToHostname { get; set; }
}

public class OcspResponse
{
    [JsonPropertyName("certificate_status")]
    public string CertificateStatus { get; set; } = string.Empty;

    [JsonPropertyName("next_update")]
    public DateTime NextUpdate { get; set; }

    [JsonPropertyName("produced_at")]
    public DateTime ProducedAt { get; set; }

    [JsonPropertyName("response_status")]
    public string ResponseStatus { get; set; } = string.Empty;

    [JsonPropertyName("revocation_time")]
    public object? RevocationTime { get; set; }

    [JsonPropertyName("serial_number")]
    public double SerialNumber { get; set; }

    [JsonPropertyName("this_update")]
    public DateTime ThisUpdate { get; set; }
}

public class Oid
{
    [JsonPropertyName("dotted_string")]
    public string DottedString { get; set; } = string.Empty;

    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;
}

public class OpensslCcsInjection
{
    [JsonPropertyName("error_reason")]
    public object? ErrorReason { get; set; }

    [JsonPropertyName("error_trace")]
    public object? ErrorTrace { get; set; }

    [JsonPropertyName("result")]
    public Result? Result { get; set; }

    [JsonPropertyName("status")]
    public string Status { get; set; } = string.Empty;
}

public class PathValidationResult
{
    [JsonPropertyName("openssl_error_string")]
    public object? OpensslErrorString { get; set; }

    [JsonPropertyName("trust_store")]
    public TrustStore TrustStore { get; set; } = new();

    [JsonPropertyName("verified_certificate_chain")]
    public List<VerifiedCertificateChain> VerifiedCertificateChain { get; set; } = new();

    [JsonPropertyName("was_validation_successful")]
    public bool WasValidationSuccessful { get; set; }
}

public class PublicKey
{
    [JsonPropertyName("algorithm")]
    public string Algorithm { get; set; } = string.Empty;

    [JsonPropertyName("ec_curve_name")]
    public object? EcCurveName { get; set; }

    [JsonPropertyName("ec_x")]
    public object? EcX { get; set; }

    [JsonPropertyName("ec_y")]
    public object? EcY { get; set; }

    [JsonPropertyName("key_size")]
    public int KeySize { get; set; }

    [JsonPropertyName("rsa_e")]
    public int? RsaE { get; set; }

    [JsonPropertyName("rsa_n")]
    public double? RsaN { get; set; }
}

public class ReceivedCertificateChain
{
    [JsonPropertyName("as_pem")]
    public string AsPem { get; set; } = string.Empty;

    [JsonPropertyName("fingerprint_sha1")]
    public string FingerprintSha1 { get; set; } = string.Empty;

    [JsonPropertyName("fingerprint_sha256")]
    public string FingerprintSha256 { get; set; } = string.Empty;

    [JsonPropertyName("hpkp_pin")]
    public string HpkpPin { get; set; } = string.Empty;

    [JsonPropertyName("issuer")]
    public Issuer Issuer { get; set; } = new();

    [JsonPropertyName("not_valid_after")]
    public DateTime NotValidAfter { get; set; }

    [JsonPropertyName("not_valid_before")]
    public DateTime NotValidBefore { get; set; }

    [JsonPropertyName("public_key")]
    public PublicKey PublicKey { get; set; } = new();

    [JsonPropertyName("serial_number")]
    public double SerialNumber { get; set; }

    [JsonPropertyName("signature_algorithm_oid")]
    public SignatureAlgorithmOid SignatureAlgorithmOid { get; set; } = new();

    [JsonPropertyName("signature_hash_algorithm")]
    public SignatureHashAlgorithm SignatureHashAlgorithm { get; set; } = new();

    [JsonPropertyName("subject")]
    public Subject Subject { get; set; } = new();

    [JsonPropertyName("subject_alternative_name")]
    public SubjectAlternativeName SubjectAlternativeName { get; set; } = new();
}

public class RejectedCipherSuite
{
    [JsonPropertyName("cipher_suite")]
    public SslyzeCipherSuite CipherSuite { get; set; } = new();

    [JsonPropertyName("error_message")]
    public string ErrorMessage { get; set; } = string.Empty;
}

public class RejectedCurf
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("openssl_nid")]
    public int OpensslNid { get; set; }
}

public class Result
{
    [JsonPropertyName("certificate_deployments")]
    public List<CertificateDeployment> CertificateDeployments { get; set; } = new();

    [JsonPropertyName("hostname_used_for_server_name_indication")]
    public string HostnameUsedForServerNameIndication { get; set; } = string.Empty;

    [JsonPropertyName("accepted_cipher_suites")]
    public List<AcceptedCipherSuite> AcceptedCipherSuites { get; set; } = new();

    [JsonPropertyName("is_tls_version_supported")]
    public bool IsTlsVersionSupported { get; set; }

    [JsonPropertyName("rejected_cipher_suites")]
    public List<RejectedCipherSuite> RejectedCipherSuites { get; set; } = new();

    [JsonPropertyName("tls_version_used")]
    public string TlsVersionUsed { get; set; } = string.Empty;

    [JsonPropertyName("supports_compression")]
    public bool SupportsCompression { get; set; }

    [JsonPropertyName("rejected_curves")]
    public List<RejectedCurf> RejectedCurves { get; set; } = new();

    [JsonPropertyName("supported_curves")]
    public List<SupportedCurf> SupportedCurves { get; set; } = new();

    [JsonPropertyName("supports_ecdh_key_exchange")]
    public bool SupportsEcdhKeyExchange { get; set; }

    [JsonPropertyName("is_vulnerable_to_heartbleed")]
    public bool IsVulnerableToHeartbleed { get; set; }

    [JsonPropertyName("is_vulnerable_to_ccs_injection")]
    public bool IsVulnerableToCcsInjection { get; set; }

    [JsonPropertyName("robot_result")]
    public string RobotResult { get; set; } = string.Empty;

    [JsonPropertyName("is_vulnerable_to_client_renegotiation_dos")]
    public bool IsVulnerableToClientRenegotiationDos { get; set; }

    [JsonPropertyName("supports_secure_renegotiation")]
    public bool SupportsSecureRenegotiation { get; set; }
}

public class Robot
{
    [JsonPropertyName("error_reason")]
    public object? ErrorReason { get; set; }

    [JsonPropertyName("error_trace")]
    public object? ErrorTrace { get; set; }

    [JsonPropertyName("result")]
    public Result? Result { get; set; }

    [JsonPropertyName("status")]
    public string Status { get; set; } = string.Empty;
}

public class ScanResult
{
    [JsonPropertyName("certificate_info")]
    public CertificateInfo? CertificateInfo { get; set; }

    [JsonPropertyName("elliptic_curves")]
    public EllipticCurves? EllipticCurves { get; set; }

    [JsonPropertyName("heartbleed")]
    public Heartbleed? Heartbleed { get; set; }

    [JsonPropertyName("http_headers")]
    public HttpHeaders? HttpHeaders { get; set; }

    [JsonPropertyName("openssl_ccs_injection")]
    public OpensslCcsInjection? OpensslCcsInjection { get; set; }

    [JsonPropertyName("robot")]
    public Robot? Robot { get; set; }

    [JsonPropertyName("session_renegotiation")]
    public SessionRenegotiation? SessionRenegotiation { get; set; }

    [JsonPropertyName("session_resumption")]
    public SessionResumption? SessionResumption { get; set; }

    [JsonPropertyName("ssl_2_0_cipher_suites")]
    public Ssl20CipherSuites? Ssl20CipherSuites { get; set; }

    [JsonPropertyName("ssl_3_0_cipher_suites")]
    public Ssl30CipherSuites? Ssl30CipherSuites { get; set; }

    [JsonPropertyName("tls_1_0_cipher_suites")]
    public Tls10CipherSuites? Tls10CipherSuites { get; set; }

    [JsonPropertyName("tls_1_1_cipher_suites")]
    public Tls11CipherSuites? Tls11CipherSuites { get; set; }

    [JsonPropertyName("tls_1_2_cipher_suites")]
    public Tls12CipherSuites? Tls12CipherSuites { get; set; }

    [JsonPropertyName("tls_1_3_cipher_suites")]
    public Tls13CipherSuites? Tls13CipherSuites { get; set; }

    [JsonPropertyName("tls_1_3_early_data")]
    public Tls13EarlyData? Tls13EarlyData { get; set; }

    [JsonPropertyName("tls_compression")]
    public TlsCompression? TlsCompression { get; set; }

    [JsonPropertyName("tls_fallback_scsv")]
    public TlsFallbackScsv? TlsFallbackScsv { get; set; }
}

public class ServerLocation
{
    [JsonPropertyName("connection_type")]
    public string ConnectionType { get; set; } = string.Empty;

    [JsonPropertyName("hostname")]
    public string Hostname { get; set; } = string.Empty;

    [JsonPropertyName("http_proxy_settings")]
    public object? HttpProxySettings { get; set; }

    [JsonPropertyName("ip_address")]
    public string IpAddress { get; set; } = string.Empty;

    [JsonPropertyName("port")]
    public int Port { get; set; }
}

public class ServerScanResult
{
    [JsonPropertyName("connectivity_error_trace")]
    public object? ConnectivityErrorTrace { get; set; }

    [JsonPropertyName("connectivity_result")]
    public ConnectivityResult? ConnectivityResult { get; set; }

    [JsonPropertyName("connectivity_status")]
    public string ConnectivityStatus { get; set; } = string.Empty;

    [JsonPropertyName("network_configuration")]
    public NetworkConfiguration? NetworkConfiguration { get; set; }

    [JsonPropertyName("scan_result")]
    public ScanResult? ScanResult { get; set; }

    [JsonPropertyName("scan_status")]
    public string ScanStatus { get; set; } = string.Empty;

    [JsonPropertyName("server_location")]
    public ServerLocation? ServerLocation { get; set; }

    [JsonPropertyName("uuid")]
    public string Uuid { get; set; } = string.Empty;
}

public class SessionRenegotiation
{
    [JsonPropertyName("error_reason")]
    public object? ErrorReason { get; set; }

    [JsonPropertyName("error_trace")]
    public object? ErrorTrace { get; set; }

    [JsonPropertyName("result")]
    public Result? Result { get; set; }

    [JsonPropertyName("status")]
    public string Status { get; set; } = string.Empty;
}

public class SessionResumption
{
    [JsonPropertyName("error_reason")]
    public object? ErrorReason { get; set; }

    [JsonPropertyName("error_trace")]
    public object? ErrorTrace { get; set; }

    [JsonPropertyName("result")]
    public object? Result { get; set; }

    [JsonPropertyName("status")]
    public string Status { get; set; } = string.Empty;
}

public class SignatureAlgorithmOid
{
    [JsonPropertyName("dotted_string")]
    public string DottedString { get; set; } = string.Empty;

    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;
}

public class SignatureHashAlgorithm
{
    [JsonPropertyName("digest_size")]
    public int DigestSize { get; set; }

    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;
}

public class Ssl20CipherSuites
{
    [JsonPropertyName("error_reason")]
    public object? ErrorReason { get; set; }

    [JsonPropertyName("error_trace")]
    public object? ErrorTrace { get; set; }

    [JsonPropertyName("result")]
    public Result? Result { get; set; }

    [JsonPropertyName("status")]
    public string Status { get; set; } = string.Empty;
}

public class Ssl30CipherSuites
{
    [JsonPropertyName("error_reason")]
    public object? ErrorReason { get; set; }

    [JsonPropertyName("error_trace")]
    public object? ErrorTrace { get; set; }

    [JsonPropertyName("result")]
    public Result? Result { get; set; }

    [JsonPropertyName("status")]
    public string Status { get; set; } = string.Empty;
}

public class Subject
{
    [JsonPropertyName("attributes")]
    public List<Attribute> Attributes { get; set; } = new();

    [JsonPropertyName("rfc4514_string")]
    public string Rfc4514String { get; set; } = string.Empty;
}

public class SubjectAlternativeName
{
    [JsonPropertyName("dns_names")]
    public List<string> DnsNames { get; set; } = new();

    [JsonPropertyName("ip_addresses")]
    public List<object> IpAddresses { get; set; } = new();
}

public class SupportedCurf
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("openssl_nid")]
    public int OpensslNid { get; set; }
}

public class Tls10CipherSuites
{
    [JsonPropertyName("error_reason")]
    public object? ErrorReason { get; set; }

    [JsonPropertyName("error_trace")]
    public object? ErrorTrace { get; set; }

    [JsonPropertyName("result")]
    public Result? Result { get; set; }

    [JsonPropertyName("status")]
    public string Status { get; set; } = string.Empty;
}

public class Tls11CipherSuites
{
    [JsonPropertyName("error_reason")]
    public object? ErrorReason { get; set; }

    [JsonPropertyName("error_trace")]
    public object? ErrorTrace { get; set; }

    [JsonPropertyName("result")]
    public Result? Result { get; set; }

    [JsonPropertyName("status")]
    public string Status { get; set; } = string.Empty;
}

public class Tls12CipherSuites
{
    [JsonPropertyName("error_reason")]
    public object? ErrorReason { get; set; }

    [JsonPropertyName("error_trace")]
    public object? ErrorTrace { get; set; }

    [JsonPropertyName("result")]
    public Result? Result { get; set; }

    [JsonPropertyName("status")]
    public string Status { get; set; } = string.Empty;
}

public class Tls13CipherSuites
{
    [JsonPropertyName("error_reason")]
    public object? ErrorReason { get; set; }

    [JsonPropertyName("error_trace")]
    public object? ErrorTrace { get; set; }

    [JsonPropertyName("result")]
    public Result? Result { get; set; }

    [JsonPropertyName("status")]
    public string Status { get; set; } = string.Empty;
}

public class Tls13EarlyData
{
    [JsonPropertyName("error_reason")]
    public object? ErrorReason { get; set; }

    [JsonPropertyName("error_trace")]
    public object? ErrorTrace { get; set; }

    [JsonPropertyName("result")]
    public object? Result { get; set; }

    [JsonPropertyName("status")]
    public string Status { get; set; } = string.Empty;
}

public class TlsCompression
{
    [JsonPropertyName("error_reason")]
    public object? ErrorReason { get; set; }

    [JsonPropertyName("error_trace")]
    public object? ErrorTrace { get; set; }

    [JsonPropertyName("result")]
    public Result? Result { get; set; }

    [JsonPropertyName("status")]
    public string Status { get; set; } = string.Empty;
}

public class TlsFallbackScsv
{
    [JsonPropertyName("error_reason")]
    public object? ErrorReason { get; set; }

    [JsonPropertyName("error_trace")]
    public object? ErrorTrace { get; set; }

    [JsonPropertyName("result")]
    public object? Result { get; set; }

    [JsonPropertyName("status")]
    public string Status { get; set; } = string.Empty;
}

public class TrustStore
{
    [JsonPropertyName("ev_oids")]
    public List<EvOid> EvOids { get; set; } = new();

    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("path")]
    public string Path { get; set; } = string.Empty;

    [JsonPropertyName("version")]
    public string Version { get; set; } = string.Empty;
}

public class VerifiedCertificateChain
{
    [JsonPropertyName("as_pem")]
    public string AsPem { get; set; } = string.Empty;

    [JsonPropertyName("fingerprint_sha1")]
    public string FingerprintSha1 { get; set; } = string.Empty;

    [JsonPropertyName("fingerprint_sha256")]
    public string FingerprintSha256 { get; set; } = string.Empty;

    [JsonPropertyName("hpkp_pin")]
    public string HpkpPin { get; set; } = string.Empty;

    [JsonPropertyName("issuer")]
    public Issuer Issuer { get; set; } = new();

    [JsonPropertyName("not_valid_after")]
    public DateTime NotValidAfter { get; set; }

    [JsonPropertyName("not_valid_before")]
    public DateTime NotValidBefore { get; set; }

    [JsonPropertyName("public_key")]
    public PublicKey PublicKey { get; set; } = new();

    [JsonPropertyName("serial_number")]
    public double SerialNumber { get; set; }

    [JsonPropertyName("signature_algorithm_oid")]
    public SignatureAlgorithmOid SignatureAlgorithmOid { get; set; } = new();

    [JsonPropertyName("signature_hash_algorithm")]
    public SignatureHashAlgorithm SignatureHashAlgorithm { get; set; } = new();

    [JsonPropertyName("subject")]
    public Subject Subject { get; set; } = new();

    [JsonPropertyName("subject_alternative_name")]
    public SubjectAlternativeName SubjectAlternativeName { get; set; } = new();
}
