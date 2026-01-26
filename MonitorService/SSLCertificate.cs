using System;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;


namespace MonitorService
{
    public class SSLCertificate
    {
        private X509Certificate2 _serverCertificate;

        public void EnsureCertificateInstalled(int port)
        {
            try
            {
                if (_serverCertificate == null)
                {
                    _serverCertificate = GetOrCreateSelfSignedCertificate();
                }

                Console.WriteLine($"Using certificate: {_serverCertificate.Subject} (Thumbprint: {_serverCertificate.Thumbprint})");
                string appId = "{12345678-1234-1234-1234-123456789012}";
                string currentThumbprint = GetCurrentSslThumbprint(port);
                string ourThumbprint = _serverCertificate.Thumbprint.ToLowerInvariant().Replace(" ", "");

                if (currentThumbprint == null || currentThumbprint != ourThumbprint)
                {
                    Console.WriteLine("Current binding missing or incorrect. Updating SSL binding...");
                    RunNetshCommand($"http delete sslcert ipport=0.0.0.0:{port}");

                    if (RunNetshCommand($"http add sslcert ipport=0.0.0.0:{port} certhash={ourThumbprint} appid={appId}"))
                    {
                        Console.WriteLine("Certificate successfully bound to port.");
                    }
                    else
                    {
                        Console.WriteLine("Failed to bind certificate. Run the application as Administrator.");
                    }
                }
                else
                {
                    Console.WriteLine("Correct certificate already bound to port.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed during certificate binding process: {ex.Message}");
            }
        }

        private string GetCurrentSslThumbprint(int port)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = $"http show sslcert ipport=0.0.0.0:{port}",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                };

                var process = Process.Start(psi);
                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();
                var match = System.Text.RegularExpressions.Regex.Match(output, @"Certificate Hash\s*:\s*([a-fA-F0-9]+)");
                if (match.Success)
                {
                    return match.Groups[1].Value.ToLowerInvariant().Replace(" ", "");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error checking existing binding: {ex.Message}");
            }

            return null;
        }

        public bool RunNetshCommand(string arguments)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = arguments,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                var process = Process.Start(psi);
                string stdOut = process.StandardOutput.ReadToEnd();
                string stdErr = process.StandardError.ReadToEnd();
                string combinedOutput = stdOut + stdErr;
                process.WaitForExit();

                if (process.ExitCode == 0)
                {
                    Console.WriteLine($"netsh success: {arguments}");
                    return true;
                }

                Console.WriteLine($"netsh command failed: {arguments}");
                Console.WriteLine($"Exit code: {process.ExitCode}");
                if (!string.IsNullOrWhiteSpace(stdOut)) Console.WriteLine($"Output: {stdOut.Trim()}");
                if (!string.IsNullOrWhiteSpace(stdErr)) Console.WriteLine($"Error: {stdErr.Trim()}");

                if (arguments.Contains("delete sslcert") && combinedOutput.Contains("not found"))
                {
                    Console.WriteLine(" (No prior binding - cleanup success)");
                    return true;
                }
                if (arguments.Contains("add urlacl") && (combinedOutput.Contains("183") || combinedOutput.Contains("already exists")))
                {
                    Console.WriteLine(" (URL reservation already exists - success)");
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Exception running netsh '{arguments}': {ex.Message}");
                return false;
            }
        }

        public X509Certificate2 GetOrCreateSelfSignedCertificate()
        {
            const string friendlyName = "MonitorService HTTPS Cert";

            try
            {
                var machineStore = new X509Store(StoreName.My, StoreLocation.LocalMachine);
                machineStore.Open(OpenFlags.ReadOnly);

                foreach (var cert in machineStore.Certificates)
                {
                    if (cert.FriendlyName == friendlyName || cert.Subject.Contains("CN=localhost"))
                    {
                        machineStore.Close();
                        Console.WriteLine($"Found suitable certificate in LocalMachine\\My (Thumbprint: {cert.Thumbprint})");
                        return cert;
                    }
                }

                machineStore.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error searching LocalMachine\\My store: {ex.Message}");
            }

            Console.WriteLine("No suitable certificate found in LocalMachine\\My. Generating new one...");
            X509Certificate2 newCert = GenerateSelfSignedCertificate();
            newCert.FriendlyName = friendlyName;

            try
            {
                var machineStore = new X509Store(StoreName.My, StoreLocation.LocalMachine);
                machineStore.Open(OpenFlags.ReadWrite);
                machineStore.Add(newCert);
                machineStore.Close();
                Console.WriteLine("New certificate added to LocalMachine\\My store.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to add new cert to LocalMachine\\My: {ex.Message} (must run as Administrator)");
                throw;
            }

            try
            {
                var rootStore = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
                rootStore.Open(OpenFlags.ReadWrite);
                if (!rootStore.Certificates.Cast<X509Certificate2>().Any(c => c.Thumbprint.Equals(newCert.Thumbprint, StringComparison.OrdinalIgnoreCase)))
                {
                    rootStore.Add(newCert);
                    Console.WriteLine("New certificate added to LocalMachine\\Trusted Root.");
                }
                rootStore.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to trust new cert in LocalMachine\\Root: {ex.Message} (requires Administrator)");
            }

            return newCert;
        }

        private X509Certificate2 GenerateSelfSignedCertificate()
        {
            using (var rsa = RSA.Create(2048))
            {
                var request = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1"), new Oid("1.3.6.1.5.5.7.3.2") }, false));
                request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, false));
                var sanBuilder = new SubjectAlternativeNameBuilder();
                sanBuilder.AddDnsName("localhost");

                string hostName = Environment.MachineName;
                sanBuilder.AddDnsName(hostName);

                string fqdn = hostName;
                try
                {
                    fqdn = Dns.GetHostEntry(hostName).HostName;
                    if (!string.Equals(fqdn, hostName, StringComparison.OrdinalIgnoreCase))
                    {
                        sanBuilder.AddDnsName(fqdn);
                    }
                }
                catch { /* Ignore DNS failures */ }

                sanBuilder.AddIpAddress(IPAddress.Loopback);
                sanBuilder.AddIpAddress(IPAddress.IPv6Loopback);

                try
                {
                    var interfaces = NetworkInterface.GetAllNetworkInterfaces();
                    foreach (var ni in interfaces)
                    {
                        if (ni.OperationalStatus != OperationalStatus.Up) continue;

                        var props = ni.GetIPProperties();
                        foreach (var unicast in props.UnicastAddresses)
                        {
                            var addr = unicast.Address;
                            if (addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ||
                                addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                            {
                                sanBuilder.AddIpAddress(addr);
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Warning: Could not enumerate local IPs for SAN: {ex.Message}");
                }

                request.CertificateExtensions.Add(sanBuilder.Build());
                request.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority: false, hasPathLengthConstraint: false, pathLengthConstraint: 0, critical: true));
                var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(2));
                var pfxBytes = certificate.Export(X509ContentType.Pfx, "");
                return new X509Certificate2(pfxBytes, "", X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.MachineKeySet);
            }
        }
    }
}
