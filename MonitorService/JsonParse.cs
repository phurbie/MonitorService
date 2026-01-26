using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.IO;
using System.Net;
using System.Text;

namespace MonitorService
{
    public class JsonParse
    {
        public SQLStorage _sqlStorage;

        public bool IsValidServerName(string name)
        {
            if (string.IsNullOrWhiteSpace(name)) return false;
            return System.Text.RegularExpressions.Regex.IsMatch(name, @"^[a-zA-Z0-9._\- ]+$");
        }

        public SqlConnection CreateConnection()
        {
            var connection = new SqlConnection(_sqlStorage._connectionString);
            connection.Open();

            using (var useCommand = new SqlCommand($"USE {_sqlStorage._databaseName}", connection))
            {
                useCommand.ExecuteNonQuery();
            }

            return connection;
        }

        public void AddServerFromRequest(HttpListenerContext context)
        {
            var response = context.Response;

            try
            {
                string bodyContent;
                using (var reader = new StreamReader(context.Request.InputStream))
                {
                    bodyContent = reader.ReadToEnd();
                }

                dynamic data = ParseJson(bodyContent);
                string serverName = data.server.ToString();

                if (!IsValidServerName(serverName) || string.IsNullOrWhiteSpace(serverName))
                {
                    SendJsonResponse(response, "{\"success\": false, \"error\": \"" +
                        (string.IsNullOrWhiteSpace(serverName) ? "Invalid server name" : "Invalid server name format") + "\"}");
                    return;
                }

                using (var connection = CreateConnection())
                {
                    var query = @"INSERT INTO Servers (Server) VALUES (@server)";
                    using (var command = new SqlCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@server", serverName);
                        command.ExecuteNonQuery();
                    }
                }

                SendJsonResponse(response, "{\"success\": true}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error adding server: {ex.Message}");
                SendJsonResponse(response, "{\"success\": false, \"error\": \"" + ex.Message.Replace("\"", "\\\"") + "\"}");
            }
        }

        public void RemoveServerFromRequest(HttpListenerContext context)
        {
            var response = context.Response;

            try
            {
                string bodyContent;
                using (var reader = new StreamReader(context.Request.InputStream))
                {
                    bodyContent = reader.ReadToEnd();
                }

                dynamic data = ParseJson(bodyContent);
                int serverId = data.id;

                if (serverId <= 0)
                {
                    SendJsonResponse(response, "{\"success\": false, \"error\": \"Invalid server ID\"}");
                    return;
                }

                using (var connection = CreateConnection())
                {
                    var query = @"DELETE FROM Servers WHERE Id = @id";
                    using (var command = new SqlCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@id", serverId);
                        command.ExecuteNonQuery();
                    }
                }

                SendJsonResponse(response, "{\"success\": true}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error removing server: {ex.Message}");
                SendJsonResponse(response, "{\"success\": false, \"error\": \"" + ex.Message.Replace("\"", "\\\"") + "\"}");
            }
        }

        public class SnmpDataRecord
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

        public IEnumerable<SnmpDataRecord> GetLatestSnmpData()
        {
            var records = new List<SnmpDataRecord>();

            try
            {
                using (var connection = CreateConnection())
                {
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

        public string GetLatestSnmpDataAsJson()
        {
            var records = GetLatestSnmpData();
            return SerializeToJson(records);
        }

        public string ConvertToSimpleJson(IEnumerable<object> data)
        {
            if (data == null) return "[]";

            var items = new List<string>();
            foreach (var item in data)
            {
                if (item == null) continue;

                var sb = new StringBuilder();
                sb.Append("{");

                var props = item.GetType().GetProperties();
                bool first = true;

                foreach (var prop in props)
                {
                    if (!first) sb.Append(",");

                    string value = prop.GetValue(item)?.ToString() ?? "";
                    value = value.Replace("\\", "\\\\")
                                .Replace("\"", "\\\"")
                                .Replace("\n", "\\n")
                                .Replace("\r", "\\r");

                    sb.AppendFormat("\"{0}\":\"{1}\"", prop.Name, value);
                    first = false;
                }

                sb.Append("}");
                items.Add(sb.ToString());
            }

            return "[" + string.Join(",", items) + "]";
        }

        private string SerializeToJson(IEnumerable<object> objects)
        {
            if (objects == null) return "[]";

            var jsonBuilder = new StringBuilder("[");
            bool first = true;

            foreach (var obj in objects)
            {
                if (!first)
                    jsonBuilder.Append(",");
                else
                    first = false;

                jsonBuilder.Append("{");

                var props = obj.GetType().GetProperties();
                bool propFirst = true;

                foreach (var prop in props)
                {
                    if (!propFirst)
                        jsonBuilder.Append(",");
                    else
                        propFirst = false;

                    string value = prop.GetValue(obj)?.ToString() ?? "";

                    value = value.Replace("\\", "\\\\")
                                .Replace("\"", "\\\"")
                                .Replace("\r", "\\r")
                                .Replace("\n", "\\n")
                                .Replace("\t", "\\t");

                    jsonBuilder.Append($"\"{prop.Name}\":\"{value}\"");
                }

                jsonBuilder.Append("}");
            }

            jsonBuilder.Append("]");
            return jsonBuilder.ToString();
        }

        private dynamic ParseJson(string json)
        {
            if (string.IsNullOrEmpty(json)) return null;

            var result = new Dictionary<string, object>();

            try
            {
                int index = 0;
                while (index < json.Length && char.IsWhiteSpace(json[index]))
                    index++;

                if (index >= json.Length || json[index] != '{')
                    return null;

                index++;

                while (index < json.Length)
                {
                    while (index < json.Length && char.IsWhiteSpace(json[index]))
                        index++;

                    if (index >= json.Length) break;

                    if (json[index] == '}')
                        break;

                    if (json[index] != '"')
                        return null;

                    int keyStart = ++index;
                    while (index < json.Length && json[index] != '"')
                        index++;

                    string key = json.Substring(keyStart, index - keyStart);
                    index++;

                    while (index < json.Length && char.IsWhiteSpace(json[index]))
                        index++;

                    if (index >= json.Length || json[index] != ':')
                        return null;

                    index++;

                    while (index < json.Length && char.IsWhiteSpace(json[index]))
                        index++;

                    string value = "";

                    if (index < json.Length)
                    {
                        if (json[index] == '"')
                        {
                            int valueStart = ++index;
                            while (index < json.Length && json[index] != '"')
                                index++;
                            value = json.Substring(valueStart, index - valueStart);
                            index++;
                        }
                        else if (json[index] == '{')
                        {
                            int braceCount = 1;
                            int start = index;
                            index++;

                            while (index < json.Length && braceCount > 0)
                            {
                                if (json[index] == '{')
                                    braceCount++;
                                else if (json[index] == '}')
                                    braceCount--;
                                index++;
                            }
                            value = json.Substring(start, index - start);
                        }
                        else
                        {
                            int valueStart = index;
                            while (index < json.Length && !char.IsWhiteSpace(json[index])
                                   && json[index] != ',' && json[index] != '}')
                                index++;
                            value = json.Substring(valueStart, index - valueStart).Trim();
                        }
                    }

                    result[key] = value;

                    while (index < json.Length && char.IsWhiteSpace(json[index]))
                        index++;

                    if (index >= json.Length) break;

                    if (json[index] == ',')
                        index++;
                    else if (json[index] == '}')
                        break;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"JSON parsing error: {ex.Message}");
                return null;
            }

            return new JsonParserResult(result);
        }

        private class JsonParserResult
        {
            private readonly Dictionary<string, object> _data;

            public JsonParserResult(Dictionary<string, object> data)
            {
                _data = data;
            }

            public dynamic server
            {
                get
                {
                    if (_data.TryGetValue("server", out var s))
                    {
                        return s?.ToString() ?? "";
                    }
                    return "";
                }
            }

            public dynamic id => _data.TryGetValue("id", out var i) ? Convert.ToInt32(i) : 0;
        }

        public void SendHtmlResponse(HttpListenerResponse response, string htmlContent)
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

        public void SendJsonResponse(HttpListenerResponse response, string jsonContent)
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

        public string GetAllServersAsJson()
        {
            var servers = new List<object>();

            try
            {
                using (var connection = CreateConnection())
                {
                    var query = @"SELECT Id, Server FROM Servers ORDER BY Server";

                    using (var command = new SqlCommand(query, connection))
                    {
                        using (var reader = command.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                servers.Add(new
                                {
                                    Id = reader["Id"].ToString(),
                                    Server = reader["Server"].ToString()
                                });
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error retrieving servers: {ex.Message}");
                return "[]";
            }

            return SerializeToJson(servers);
        }
    }
}
