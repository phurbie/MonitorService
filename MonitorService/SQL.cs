using System;
using System.Data.SqlClient;

namespace MonitorService
{
    public class SQLStorage
    {
        public readonly string _connectionString;
        public readonly string _databaseName = "MonitorDB";

        public SQLStorage()
        {
            _connectionString = @"Data Source=localhost\MONITORSERVICE;Integrated Security=True;Encrypt=true;TrustServerCertificate=True;";
        }

        public void StoreSNMPData(DateTime timestamp, string ipAddress, int port, string errorInfo, string snmpVersion, string community, string pdu, string request, string varBind, string hexData)
        {
            try
            {
                SqlConnection connection = new SqlConnection(_connectionString);
                try
                {
                    connection.Open();
                    CreateDatabaseIfNotExists(connection);

                    string query = $@"
                        INSERT INTO [{_databaseName}].[dbo].[SNMPTrap] 
                            (Date, Location, Error, SNMPv, Community, PDU, Request, VarBind, FullHex) 
                        VALUES (@date, @location, @error, @snmpv, @community, @pdu, @request, @varbind, @fullhex)";

                    SqlCommand command = new SqlCommand(query, connection);
                    try
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
                    finally
                    {
                        command.Dispose();
                    }
                }
                finally
                {
                    connection.Close();
                    connection.Dispose();
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
                using (SqlConnection connection = new SqlConnection(_connectionString))
                {
                    connection.Open();
                    CreateDatabaseIfNotExists(connection);

                    string createTableQuery1 = $@"
                IF NOT EXISTS (
                    SELECT * FROM INFORMATION_SCHEMA.TABLES 
                    WHERE TABLE_SCHEMA = 'dbo' AND TABLE_NAME = 'SNMPTrap'
                )
                CREATE TABLE [{_databaseName}].[dbo].[SNMPTrap] (
                    Id INT IDENTITY(1,1) PRIMARY KEY,
                    Date DATETIME NOT NULL,
                    Location NVARCHAR(255) NOT NULL,
                    Error NVARCHAR(MAX) NOT NULL,
                    SNMPv NVARCHAR(50) NOT NULL,
                    Community NVARCHAR(255) NOT NULL,
                    PDU NVARCHAR(50) NOT NULL,
                    Request NVARCHAR(255) NOT NULL,
                    VarBind NVARCHAR(MAX) NOT NULL,
                    FullHex NVARCHAR(MAX) NOT NULL
                )";

                    string createTableQuery2 = $@"
                IF NOT EXISTS (
                    SELECT * FROM INFORMATION_SCHEMA.TABLES 
                    WHERE TABLE_SCHEMA = 'dbo' AND TABLE_NAME = 'Servers'
                )
                CREATE TABLE [{_databaseName}].[dbo].[Servers] (
                    Id INT IDENTITY(1,1) PRIMARY KEY,
                    Server NVARCHAR(255) NOT NULL
                )";

                    ExecuteNonQueryWithDb(connection, createTableQuery1);
                    ExecuteNonQueryWithDb(connection, createTableQuery2);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error initializing database: {ex.Message}");
            }
        }

        private void CreateDatabaseIfNotExists(SqlConnection connection)
        {
            string checkDbQuery = $"SELECT name FROM sys.databases WHERE name = '{_databaseName}'";
            SqlCommand checkCommand = new SqlCommand(checkDbQuery, connection);
            try
            {
                object result = checkCommand.ExecuteScalar();
                if (result == null || result.ToString() != _databaseName)
                {
                    string createDbQuery = $"CREATE DATABASE [{_databaseName}]";
                    SqlCommand createCommand = new SqlCommand(createDbQuery, connection);
                    try
                    {
                        createCommand.ExecuteNonQuery();
                    }
                    finally
                    {
                        createCommand.Dispose();
                    }
                }
            }
            finally
            {
                checkCommand.Dispose();
            }
        }

        private void ExecuteNonQueryWithDb(SqlConnection connection, string query)
        {
            SqlCommand command = new SqlCommand(query, connection);
            try
            {
                command.ExecuteNonQuery();
            }
            finally
            {
                command.Dispose();
            }
        }
    }
}