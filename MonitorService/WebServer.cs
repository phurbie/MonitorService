using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace MonitorService
{
    public class WebServer
    {
        private readonly SQLStorage _sqlStorage;
        private HttpListener _listener;
        private bool _isRunning;
        private X509Certificate2 _serverCertificate;

        public WebServer()
        {
            _sqlStorage = new SQLStorage();
            _serverCertificate = GetOrCreateSelfSignedCertificate();
        }

        private void EnsureCertificateInstalled(int port = 8443)
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
                    bool success = RunNetshCommand($"http add sslcert ipport=0.0.0.0:{port} certhash={ourThumbprint} appid={appId}");
                    if (success)
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

        private bool RunNetshCommand(string arguments)
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

                if (process.ExitCode != 0)
                {
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

                Console.WriteLine($"netsh success: {arguments}");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Exception running netsh '{arguments}': {ex.Message}");
                return false;
            }
        }

        public void Start(int port = 8443)
        {
            if (_isRunning) return;

            try
            {
                EnsureCertificateInstalled(port);
                EnsureUrlReservation(port);
                _listener = new HttpListener();
                _listener.Prefixes.Add($"https://+:{port}/");
                _listener.Start();
                _isRunning = true;

                Task.Run(async () =>
                {
                    while (_isRunning)
                    {
                        try
                        {
                            var context = await _listener.GetContextAsync();
                            ProcessRequest(context);
                        }
                        catch (Exception ex)
                        {
                            if (_isRunning) Console.WriteLine($"Web server error: {ex.Message}");
                        }
                    }
                });

                Console.WriteLine($"HTTPS Web server started on https://<any-host-or-ip>:{port}/");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error starting web server: {ex.Message}");
            }
        }

        public void Stop()
        {
            _isRunning = false;
            _listener?.Stop();
            Console.WriteLine("Web server stopped");
        }

        private X509Certificate2 GetOrCreateSelfSignedCertificate()
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

        private void EnsureUrlReservation(int port = 8443)
        {
            try
            {
                string prefix = $"https://+:{port}/";
                string user = "everyone";
                Console.WriteLine($"Ensuring URL reservation for {prefix}");
                bool added = RunNetshCommand($"http add urlacl url={prefix} user={user}");

                if (added)
                {
                    Console.WriteLine("URL reservation added successfully.");
                    return;
                }

                var psi = new ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = $"http show urlacl url={prefix}",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                var process = Process.Start(psi);
                process.WaitForExit();

                if (process.ExitCode == 0)
                {
                    Console.WriteLine("URL reservation already exists.");
                }
                else
                {
                    Console.WriteLine("Failed to reserve URL. Run the application as Administrator.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error during URL reservation: {ex.Message}");
            }
        }

        private void ProcessRequest(HttpListenerContext context)
        {
            var response = context.Response;

            try
            {
                if (context.Request.Url.AbsolutePath == "/")
                {
                    SendHtmlResponse(response, GenerateHomePage());
                }
                else if (context.Request.Url.AbsolutePath == "/refresh")
                {
                    SendJsonResponse(response, GetLatestSnmpDataAsJson());
                }
                else
                {
                    response.StatusCode = 404;
                    response.Close();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error processing request: {ex.Message}");
                response.StatusCode = 500;
                response.Close();
            }
        }

        private string GenerateHomePage()
        {
            var html = @"
<!DOCTYPE html>
<html>
<head>
    <title>SNMP Trap Data</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: black;
        }
        
        .container {
            margin: 0 auto;
            background-color: #090909;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        h1 {
            color: white;
            text-align: center;
            border-bottom: 2px solid #0C1D77;
            padding-bottom: 10px;
        }
        
        .styled-button {
            background-color: #0C1D77;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
        }
        
        .content-section {
            margin: 20px 0;
            padding: 15px;
            border-left: 4px solid #4CAF50;
            background-color: #f9f9f9;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
            color: white;
        }
        
        th {
            background-color: #0C1D77;
            color: white;
        }
    </style>
</head>
<body>
    <div class='container'>
        <h1>Recent SNMP Trap Data</h1>
        <button id='refreshBtn' class='styled-button'>Refresh Data</button>
        <div id='data-container'>
            <table id='snmpTable'>
                <thead>
                    <tr>
                        <th>Date</th>
                        <th>Location</th>
                        <th>Error</th>
                        <th>SNMPv</th>
                        <th>Community</th>
                        <th>PDU</th>
                        <th>Request</th>
                        <th>VarBind</th>
                        <th>FullHex</th>
                    </tr>
                </thead>
                <tbody id='tableBody'>";
            try
            {
                var data = GetLatestSnmpData();

                foreach (var row in data)
                {
                    html += $"<tr>" +
                            $"<td>{row.Date}</td>" +
                            $"<td>{row.Location}</td>" +
                            $"<td>{row.Error}</td>" +
                            $"<td>{row.SNMPv}</td>" +
                            $"<td>{row.Community}</td>" +
                            $"<td>{row.PDU}</td>" +
                            $"<td>{row.Request}</td>" +
                            $"<td>{row.VarBind}</td>" +
                            $"<td>{row.FullHex}</td>" +
                            "</tr>";
                }
            }
            catch (Exception ex)
            {
                html += $"<tr><td colspan='9'>Error loading data: {ex.Message}</td></tr>";
            }

            html += @"
                </tbody>
            </table>
        </div>
    </div>
    <script>
        document.getElementById('refreshBtn').addEventListener('click', function() {
            const refreshBtn = this;
            const originalText = refreshBtn.innerHTML;
            refreshBtn.disabled = true;
            refreshBtn.innerHTML = 'Loading...';
            
            fetch('/refresh')
                .then(response => response.json())
                .then(data => {
                    const tableBody = document.getElementById('tableBody');
                    tableBody.innerHTML = '';
                    
                    data.forEach(row => {
                        const tr = document.createElement('tr');
                        tr.innerHTML = `
                            <td>${row.Date}</td>
                            <td>${row.Location}</td>
                            <td>${row.Error}</td>
                            <td>${row.SNMPv}</td>
                            <td>${row.Community}</td>
                            <td>${row.PDU}</td>
                            <td>${row.Request}</td>
                            <td>${row.VarBind}</td>
                            <td>${row.FullHex}</td>
                        `;
                        tableBody.appendChild(tr);
                    });
                })
                .catch(error => {
                    console.error('Error refreshing data:', error);
                    alert('Failed to refresh data. Please try again.');
                })
                .finally(() => {
                    // Re-enable button
                    refreshBtn.disabled = false;
                    refreshBtn.innerHTML = originalText;
                });
        });
    </script>
</body>
</html>";
            return html;
        }

        private class SnmpDataRecord
        {
            public string Date { get; set; }
            public string Location { get; set; }
            public string Error { get; set; }
            public string SNMPv { get; set; }
            public string Community { get; set; }
            public string PDU { get; set; }
            public string Request { get; set; }
            public string VarBind { get; set; }
            public string FullHex { get; set; }
        }

        private IEnumerable<SnmpDataRecord> GetLatestSnmpData()
        {
            var records = new List<SnmpDataRecord>();

            try
            {
                using (var connection = new SqlConnection(_sqlStorage._connectionString))
                {
                    connection.Open();
                    var useDbQuery = $"USE {_sqlStorage._databaseName}";
                    using (var useCommand = new SqlCommand(useDbQuery, connection))
                    {
                        useCommand.ExecuteNonQuery();
                    }

                    var query = @"SELECT TOP 50 Date, Location, Error, SNMPv, Community, PDU, Request, VarBind, FullHex FROM SNMPTrap ORDER BY Date DESC";

                    using (var command = new SqlCommand(query, connection))
                    {
                        using (var reader = command.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                records.Add(new SnmpDataRecord
                                {
                                    Date = reader["Date"].ToString(),
                                    Location = reader["Location"].ToString(),
                                    Error = reader["Error"].ToString(),
                                    SNMPv = reader["SNMPv"].ToString(),
                                    Community = reader["Community"].ToString(),
                                    PDU = reader["PDU"].ToString(),
                                    Request = reader["Request"].ToString(),
                                    VarBind = reader["VarBind"].ToString(),
                                    FullHex = reader["FullHex"].ToString()
                                });
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error retrieving data: {ex.Message}");
            }
            return records;
        }

        private string GetLatestSnmpDataAsJson()
        {
            var records = new List<SnmpDataRecord>();

            try
            {
                using (var connection = new SqlConnection(_sqlStorage._connectionString))
                {
                    connection.Open();
                    var useDbQuery = $"USE {_sqlStorage._databaseName}";
                    using (var useCommand = new SqlCommand(useDbQuery, connection))
                    {
                        useCommand.ExecuteNonQuery();
                    }

                    var query = @"SELECT TOP 50 Date, Location, Error, SNMPv, Community, PDU, Request, VarBind, FullHex FROM SNMPTrap ORDER BY Date DESC";

                    using (var command = new SqlCommand(query, connection))
                    {
                        using (var reader = command.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                records.Add(new SnmpDataRecord
                                {
                                    Date = reader["Date"].ToString(),
                                    Location = reader["Location"].ToString(),
                                    Error = reader["Error"].ToString(),
                                    SNMPv = reader["SNMPv"].ToString(),
                                    Community = reader["Community"].ToString(),
                                    PDU = reader["PDU"].ToString(),
                                    Request = reader["Request"].ToString(),
                                    VarBind = reader["VarBind"].ToString(),
                                    FullHex = reader["FullHex"].ToString()
                                });
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error retrieving data: {ex.Message}");
                return "[]";
            }

            // Proper escaping helper
            string EscapeJson(string s) => string.IsNullOrEmpty(s)
                ? ""
                : s.Replace("\\", "\\\\")
                   .Replace("\"", "\\\"")
                   .Replace("\r", "\\r")
                   .Replace("\n", "\\n")
                   .Replace("\t", "\\t");

            var jsonBuilder = new StringBuilder("[");
            for (int i = 0; i < records.Count; i++)
            {
                var r = records[i];
                jsonBuilder.Append("{");
                jsonBuilder.Append($"\"Date\":\"{EscapeJson(r.Date)}\",");
                jsonBuilder.Append($"\"Location\":\"{EscapeJson(r.Location)}\",");
                jsonBuilder.Append($"\"Error\":\"{EscapeJson(r.Error)}\",");
                jsonBuilder.Append($"\"SNMPv\":\"{EscapeJson(r.SNMPv)}\",");
                jsonBuilder.Append($"\"Community\":\"{EscapeJson(r.Community)}\",");
                jsonBuilder.Append($"\"PDU\":\"{EscapeJson(r.PDU)}\",");
                jsonBuilder.Append($"\"Request\":\"{EscapeJson(r.Request)}\",");
                jsonBuilder.Append($"\"VarBind\":\"{EscapeJson(r.VarBind)}\",");
                jsonBuilder.Append($"\"FullHex\":\"{EscapeJson(r.FullHex)}\"");
                jsonBuilder.Append("}");

                if (i < records.Count - 1) jsonBuilder.Append(",");
            }
            jsonBuilder.Append("]");
            return jsonBuilder.ToString();
        }

        private void SendHtmlResponse(HttpListenerResponse response, string htmlContent)
        {
            var buffer = Encoding.UTF8.GetBytes(htmlContent);
            response.ContentLength64 = buffer.Length;
            response.ContentType = "text/html; charset=utf-8";

            using (var output = response.OutputStream)
            {
                output.Write(buffer, 0, buffer.Length);
            }

            response.Close();
        }

        private void SendJsonResponse(HttpListenerResponse response, string jsonContent)
        {
            var buffer = Encoding.UTF8.GetBytes(jsonContent);
            response.ContentLength64 = buffer.Length;
            response.ContentType = "application/json; charset=utf-8";

            using (var output = response.OutputStream)
            {
                output.Write(buffer, 0, buffer.Length);
            }

            response.Close();
        }
    }
}