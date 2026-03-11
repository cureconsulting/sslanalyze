using System.Text.Json;
using RestSharp;
using sslanalyze.Models;

namespace sslanalyze.Services;

 public class CipherSuiteAPI
    {
        public async Task<List<CipherSuite>> GetCipherSuitesAsync()
        {
            var intranetClient = new RestClient("https://ciphersuite.info/api");
            var request = new RestRequest("/cs");
            var response = await intranetClient.ExecuteAsync(request);
            if (string.IsNullOrEmpty(response.Content))
                return new List<CipherSuite>();

            var csr = JsonSerializer.Deserialize<CipherSuiteResponse>(response.Content);
            if (csr == null)
                return new List<CipherSuite>();

            return await getCipherSuiteList(csr);
        }
        private async Task<List<CipherSuite>> getCipherSuiteList(CipherSuiteResponse csr)
        {
            var suites = new List<CipherSuite>();

            foreach (var cskvp in csr.CipherSuites)
            {
                var csName = cskvp.First().Key;
                var cs = cskvp.First().Value;

                var suite = new CipherSuite
                {
                    Name = csName,
                    Protocol = cs.ProtocolVersion,
                    HashAlgorithm = cs.HashAlgorithm,
                    EncryptionAlgorithm = cs.EncAlgorithm,
                    Recommended = cs.Security == "recommended",
                    Secure = (cs.Security == "recommended" ? true : cs.Security == "secure")
                };

                await Task.Run(() => cs.TlsVersion.ForEach(v => suite.TLSVersion.Add(v)));
                suites.Add(suite);
            }

            return suites;
        }
    }
