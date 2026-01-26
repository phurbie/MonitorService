using System;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace MonitorService
{
    public class WebServer
    {
        private readonly SQLStorage _sqlStorage;
        private readonly SSLCertificate _certService;
        private readonly JsonParse _jsonParse;
        private readonly RemoteCalls _remoteCall;
        private HttpListener _listener;
        private bool _isRunning;
        private X509Certificate2 _serverCertificate;

        public WebServer(SQLStorage sqlStorage, SSLCertificate certService, RemoteCalls remoteCall)
        {
            _sqlStorage = sqlStorage;
            _certService = certService;
            _remoteCall = remoteCall;
            _serverCertificate = _certService.GetOrCreateSelfSignedCertificate();
            _jsonParse = new JsonParse() { _sqlStorage = _sqlStorage };
        }

        public void Start(int port = 8443)
        {
            if (_isRunning) return;

            try
            {
                _certService.EnsureCertificateInstalled(port);
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

                Console.WriteLine($"HTTPS Web server started on https://*:{port}/");
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

        private void EnsureUrlReservation(int port = 8443)
        {
            try
            {
                string prefix = $"https://+:{port}/";
                string user = "everyone";
                Console.WriteLine($"Ensuring URL reservation for {prefix}");
                bool added = _certService.RunNetshCommand($"http add urlacl url={prefix} user={user}");

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
                    _jsonParse.SendHtmlResponse(response, GenerateHomePage());
                }
                else if (context.Request.Url.AbsolutePath == "/refresh")
                {
                    _jsonParse.SendJsonResponse(response, _jsonParse.GetLatestSnmpDataAsJson());
                }
                else if (context.Request.Url.AbsolutePath == "/servers")
                {
                    _jsonParse.SendJsonResponse(response, _jsonParse.GetAllServersAsJson());
                }
                else if (context.Request.Url.AbsolutePath == "/add-server" && context.Request.HttpMethod == "POST")
                {
                    _jsonParse.AddServerFromRequest(context);
                }
                else if (context.Request.Url.AbsolutePath == "/remove-server" && context.Request.HttpMethod == "POST")
                {
                    _jsonParse.RemoveServerFromRequest(context);
                }
                else if (context.Request.Url.AbsolutePath == "/disk-space")
                {
                    string serverName = null;
                    try
                    {
                        serverName = context.Request.QueryString["server"];

                        if (!string.IsNullOrEmpty(serverName) && !_jsonParse.IsValidServerName(serverName))
                        {
                            Console.WriteLine($"Invalid server name format: {serverName}");
                            serverName = null;
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error parsing disk-space query parameter: {ex.Message}");
                        serverName = null;
                    }

                    var diskData = _remoteCall.GetDiskSpaceData(serverName);
                    string json = _jsonParse.ConvertToSimpleJson(diskData);
                    _jsonParse.SendJsonResponse(response, json);
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
    <title>Monitor Service</title>
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
            background-color: #090909;
            color: white;
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
        
        .server-input-group {
            margin: 10px 0;
        }
        
        .server-input-group input {
            padding: 8px;
            width: 200px;
            margin-right: 10px;
        }
        
        /* Disk space table styling */
        .disk-space-table {
            margin-top: 15px;
            border-collapse: collapse;
            width: 100%;
        }
        
        .disk-space-table th, .disk-space-table td {
            padding: 8px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        
        .disk-space-table th {
            background-color: #0C1D77;
            color: white;
        }
    </style>
</head>
<body>
    <div class='container'>
        <h1>Monitor Service</h1>
        <div class=""content-section"">
            <h2>Disk Space</h2>
            <div class=""server-input-group"">
                <input type=""text"" id=""newServerInput"" placeholder=""Enter server name"" />
                <button onclick=""addServer()"" class='styled-button'>Add Server</button>
                <button onclick=""refreshServers()"" class='styled-button'>Refresh Servers</button>
            </div>
            <div id=""serverList"">
                
            </div>
        </div>
        <div class=""content-section"">
            <h2>SNMP Data<button id='refreshBtn' class='styled-button'>Refresh Data</button></h2>
        </div>
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
                var data = _jsonParse.GetLatestSnmpData();

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
        document.addEventListener('DOMContentLoaded', function() {
            refreshServers();
            loadSnmpData();
        });

        function loadSnmpData() {
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
                    console.error('Error loading data:', error);
                });
        }

        function addServer() {
            const input = document.getElementById('newServerInput');
            const serverName = input.value.trim();
            
            if (!serverName) {
                alert('Please enter a valid server name');
                return;
            }
            
            fetch('/add-server', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ server: serverName })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    input.value = '';
                    refreshServers();
                    alert('Server added successfully');
                } else {
                    alert('Error adding server: ' + data.error);
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Failed to add server');
            });
        }
        
        function removeServer(serverId) {
            if (!confirm('Are you sure you want to remove this server?')) return;
            
            fetch('/remove-server', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ id: serverId })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    refreshServers();
                    alert('Server removed successfully');
                } else {
                    alert('Error removing server: ' + data.error);
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Failed to remove server');
            });
        }
        
        function refreshServers() {
            fetch('/servers')
                .then(response => response.json())
                .then(data => {
                    const container = document.getElementById('serverList');
                    if (data.length === 0) {
                        container.innerHTML = '<p>No servers found</p>';
                        return;
                    }

                    let html = '';
                    
                    for (let i = 0; i < data.length; i += 2) {
                        const server1 = data[i];
                        const server2 = data[i + 1];
                        
                        html += '<div style=""display:flex; width:100%; margin-bottom:10px;"">';
                        
                        if (server1) {
                            html += `
                                <div style=""width:50%; padding:0 5px;"">
                                    <h3>${server1.Server}
                                        <button onclick=""removeServer(${server1.Id})"" class='styled-button' style=""background-color:red; padding:5px 10px;font-size:12px; float:right;"">Remove Server</button>
                                    </h3>
                                    <div id=""diskSpace-${server1.Id}"">
                                        <p>Loading disk space data...</p>
                                    </div>
                                </div>
                            `;
                        }
                        
                        if (server2) {
                            html += `
                                <div style=""width:50%; padding:0 5px;"">
                                    <h3>${server2.Server}
                                        <button onclick=""removeServer(${server2.Id})"" class='styled-button' style=""background-color:red; padding:5px 10px;font-size:12px; float:right;"">Remove Server</button>
                                    </h3>
                                    <div id=""diskSpace-${server2.Id}"">
                                        <p>Loading disk space data...</p>
                                    </div>
                                </div>
                            `;
                        }
                        
                        html += '</div>';
                    }
                    
                    container.innerHTML = html;
                    
                    // Load disk space data for each server
                    data.forEach(server => {
                        loadDiskSpaceForServer(server.Id, server.Server);
                    });
                })
                .catch(error => {
                    console.error('Error loading servers:', error);
                    document.getElementById('serverList').innerHTML = '<p>Error loading servers</p>';
                });
        }

        function loadDiskSpaceForServer(serverId, serverName) {
            const url = '/disk-space?server=' + encodeURIComponent(serverName);

            fetch(url)
                .then(response => response.json())
                .then(data => {
                    const container = document.getElementById('diskSpace-' + serverId);
            
                    if (data.length === 0) {
                        container.innerHTML = '<p>No disk space data available for this server</p>';
                        return;
                    }
            
                    let htmlContent = `
                        <table class=""disk-space-table"">
                            <thead>
                                <tr>
                                    <th>Drive Letter</th>
                                    <th>Total Size</th>
                                    <th>Free Space</th>
                                    <th>Usage %</th>
                                </tr>
                            </thead>
                            <tbody>
                    `;
            
                    data.forEach(drive => {
                        const usagePercentage = parseFloat(drive.PercentageUsed) || 0;
                        let usageStyle = '';
                        
                        if (usagePercentage < 50) {
                            usageStyle = 'color: lightblue;';
                        } else if (usagePercentage >= 50 && usagePercentage < 90) {
                            usageStyle = 'color: yellow;';
                        } else { // usagePercentage >= 90
                            usageStyle = 'color: red; font-weight: bold;';
                        }
                        
                        htmlContent += `
                            <tr>
                                <td>${drive.DriveLetter}</td>
                                <td>${drive.FormattedTotalSize}</td>
                                <td>${drive.FormattedFreeSpace}</td>
                                <td style=""${usageStyle}"">${drive.PercentageUsed}%</td>
                            </tr>
                        `;
                    });
            
                    htmlContent += `
                            </tbody>
                        </table>
                    `;
            
                    container.innerHTML = htmlContent;
                })
                .catch(error => {
                    console.error('Error loading disk space data for server ' + serverName, error);
                    document.getElementById('diskSpace-' + serverId).innerHTML = 
                        '<p style=""color:red;"">Error loading disk space data: ' + error.message + '</p>';
                });
        }

        function refreshDiskSpace() {
            loadDiskSpaceData();
        }

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
    }
}