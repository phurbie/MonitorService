using System;
using System.Data.SqlClient;

namespace MonitorService
{
    public class SQLStorage
    {
        private readonly string _connectionString;
        private readonly string _databaseName = "MonitorDB";

        public SQLStorage()
        {
            _connectionString = @"Data Source=localhost\MONITORSERVICE;Integrated Security=True;";
        }

        public void StoreSNMPData(DateTime timestamp, string ipAddress, int port, string errorInfo, string snmpVersion, string community, string pdu, string request, string varBind, string hexData)
        {
            try
            {
                using (var connection = new SqlConnection(_connectionString))
                {
                    connection.Open();
                    CreateDatabaseIfNotExists(connection);
                    var useDbQuery = $"USE {_databaseName}";
                    using (var useCommand = new SqlCommand(useDbQuery, connection))
                    {
                        useCommand.ExecuteNonQuery();
                    }
                    var query = @"INSERT INTO SNMPTrap (Date, Location, Error, SNMPv, Community, PDU, Request, VarBind, FullHex) VALUES (@date, @location, @error, @snmpv, @community, @pdu, @request, @varbind, @fullhex)";
                    using (var command = new SqlCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@date", timestamp);
                        command.Parameters.AddWithValue("@location", $"{ipAddress}:{port}");
                        command.Parameters.AddWithValue("@error", errorInfo ?? "");
                        command.Parameters.AddWithValue("@snmpv", snmpVersion ?? "");
                        command.Parameters.AddWithValue("@community", community ?? "");
                        command.Parameters.AddWithValue("@pdu", pdu ?? "");
                        command.Parameters.AddWithValue("@request", request ?? "");
                        command.Parameters.AddWithValue("@varbind", varBind ?? "");
                        command.Parameters.AddWithValue("@fullhex", hexData ?? "");
                        command.ExecuteNonQuery();
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error storing SNMP data to SQL: {ex.Message}");
                throw;
            }
        }

        public void InitializeDatabase()
        {
            try
            {
                using (var connection = new SqlConnection(_connectionString))
                {
                    connection.Open();
                    CreateDatabaseIfNotExists(connection);
                    var useDbQuery = $"USE {_databaseName}";
                    using (var useCommand = new SqlCommand(useDbQuery, connection))
                    {
                        useCommand.ExecuteNonQuery();
                    }
                    var createTableQuery = @"
                        IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='SNMPTrap' AND xtype='U') CREATE TABLE SNMPTrap (Id INT IDENTITY(1,1) PRIMARY KEY, Date DATETIME NOT NULL, Location NVARCHAR(255) NOT NULL, Error NVARCHAR(MAX) NOT NULL, SNMPv NVARCHAR(50) NOT NULL, Community NVARCHAR(255) NOT NULL, PDU NVARCHAR(50) NOT NULL, Request NVARCHAR(255) NOT NULL, VarBind NVARCHAR(MAX) NOT NULL, FullHex NVARCHAR(MAX) NOT NULL)";
                    using (var command = new SqlCommand(createTableQuery, connection))
                    {
                        command.ExecuteNonQuery();
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error initializing database: {ex.Message}");
            }
        }

        private void CreateDatabaseIfNotExists(SqlConnection connection)
        {
            try
            {
                var checkDbQuery = $"SELECT name FROM sys.databases WHERE name = '{_databaseName}'";
                using (var checkCommand = new SqlCommand(checkDbQuery, connection))
                {
                    var result = checkCommand.ExecuteScalar();
                    if (result == null || result.ToString() != _databaseName)
                    {
                        var createDbQuery = $"CREATE DATABASE {_databaseName}";
                        using (var createCommand = new SqlCommand(createDbQuery, connection))
                        {
                            createCommand.ExecuteNonQuery();
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error checking/creating database: {ex.Message}");
                throw;
            }
        }
    }
}
