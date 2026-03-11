using System.Text.Json;
using Microsoft.Extensions.Logging;
using sslanalyze.Models;

namespace sslanalyze.Services;

public class SSLyzeParser
{
    protected ILogger logger;
    protected ILoggerFactory logFactory;

    public SSLyzeParser(ILoggerFactory LogFactory)
    {
        this.logger = LogFactory.CreateLogger<SSLyzeParser>();
        this.logFactory = LogFactory;

    }

    public async Task<List<SSLyzeIssue>> ParseScanDefects(string RawJsonString, CancellationToken Token = default)
    {
        var defects = new List<SSLyzeIssue>();
        var cypherSuiteAPI = new CipherSuiteAPI();
        var suites = await cypherSuiteAPI.GetCipherSuitesAsync();

        try
        {
            var scan = JsonSerializer.Deserialize<SSLyzeResponse>(RawJsonString);
            if (scan?.ServerScanResults == null)
            {
                logger.LogWarning("Failed to deserialize SSLyze response or no scan results found");
                return defects;
            }

            foreach (var scanResult in scan.ServerScanResults)
            {
                var result = scanResult?.ScanResult;
                if (result == null) continue;

                var ssl20 = result.Ssl20CipherSuites?.Result?.AcceptedCipherSuites;
                if (ssl20 is { Count: > 0 })
                {
                    var protocolDefect = new SSLyzeIssue();
                    protocolDefect.QueryName = "Weak SSL/TLS Protocols";
                    protocolDefect.QueryDescription = "The server supports SSL v2.0.";
                    defects.Add(protocolDefect);
                }

                var ssl30 = result.Ssl30CipherSuites?.Result?.AcceptedCipherSuites;
                if (ssl30 is { Count: > 0 })
                {
                    var protocolDefect = new SSLyzeIssue();
                    protocolDefect.QueryName = "Weak SSL/TLS Protocols";
                    protocolDefect.QueryDescription = "The server supports SSL v3.0.";
                    defects.Add(protocolDefect);
                }

                var tls10 = result.Tls10CipherSuites?.Result?.AcceptedCipherSuites;
                if (tls10 is { Count: > 0 })
                {
                    var protocolDefect = new SSLyzeIssue();
                    protocolDefect.QueryName = "Weak SSL/TLS Protocols";
                    protocolDefect.QueryDescription = "The server supports TLS v1.0.";
                    defects.Add(protocolDefect);
                }

                var tls11 = result.Tls11CipherSuites?.Result?.AcceptedCipherSuites;
                if (tls11 is { Count: > 0 })
                {
                    var protocolDefect = new SSLyzeIssue();
                    protocolDefect.QueryName = "Weak SSL/TLS Protocols";
                    protocolDefect.QueryDescription = "The server supports TLS v1.1.";
                    defects.Add(protocolDefect);
                }

                var tls12 = result.Tls12CipherSuites?.Result?.AcceptedCipherSuites;
                if (tls12 != null)
                {
                    foreach (var suite in tls12)
                    {
                        var name = suite?.CipherSuite?.Name;
                        if (name == null) continue;
                        var csiRslt = suites.FirstOrDefault(s => s.Name == name);
                        if (csiRslt?.Secure == false)
                            defects.Add(getIssue(csiRslt));
                    }
                }

                var tls13 = result.Tls13CipherSuites?.Result?.AcceptedCipherSuites;
                if (tls13 != null)
                {
                    foreach (var suite in tls13)
                    {
                        var name = suite?.CipherSuite?.Name;
                        if (name == null) continue;
                        var csiRslt = suites.FirstOrDefault(s => s.Name == name);
                        if (csiRslt?.Secure == false)
                            defects.Add(getIssue(csiRslt));
                    }
                }

                //OCSP Stapling
                var certDeployments = result.CertificateInfo?.Result?.CertificateDeployments;
                if (certDeployments != null)
                {
                    foreach (var certDeployment in certDeployments)
                    {
                        if (certDeployment?.OcspResponse != null && certDeployment.OcspResponse.ResponseStatus != "SUCCESSFUL")
                        {
                            var ocspDefect = new SSLyzeIssue();
                            ocspDefect.QueryName = "Missing OCSP Stapling";
                            ocspDefect.QueryDescription = $"The server does not support OCSP Stapling. (Cert serial number {certDeployment.OcspResponse.SerialNumber})";
                            defects.Add(ocspDefect);
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            logger.LogError(ex.Message, ex);
        }

        return defects;
    }

    private SSLyzeIssue getIssue(CipherSuite csiRslt)
    {
        var addlInfo = string.Empty;
        if (csiRslt.EncryptionAlgorithm.Contains("CBC"))
            addlInfo = ", which uses Circular Block Chaining (CBC)";

        if (csiRslt.Name.Contains("_DHE_"))
            addlInfo = ", which uses Diffie-Hellman Epheremal (DHE) Key Exchange";

        //TODO: Handle thinks like < bits, etc

        var cipherDefect = new SSLyzeIssue();
        cipherDefect.QueryName = "Weak SSL/TLS Ciphers";
        cipherDefect.QueryDescription = $"The server accepts the insecure '{csiRslt.Name}' cipher suite{addlInfo}.";
        return cipherDefect;
    }
}