using System;
using System.Collections.Generic;
using System.Management;

namespace MonitorService
{
    public class RemoteCalls
    {
        public List<object> GetDiskSpaceData(string serverName)
        {
            var diskInfoList = new List<object>();

            try
            {
                if (string.IsNullOrEmpty(serverName))
                {
                    using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_LogicalDisk"))
                    {
                        foreach (ManagementObject drive in searcher.Get())
                        {
                            ProcessDriveInfo(drive, serverName, diskInfoList);
                        }
                    }
                }
                else
                {
                    string remoteName = serverName.Trim().TrimStart('\\', '/');

                    if (string.Equals(remoteName, ".", StringComparison.Ordinal) ||
                        string.Equals(remoteName, "localhost", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(remoteName, Environment.MachineName, StringComparison.OrdinalIgnoreCase))
                    {
                        using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_LogicalDisk"))
                        {
                            foreach (ManagementObject drive in searcher.Get())
                            {
                                ProcessDriveInfo(drive, serverName, diskInfoList);
                            }
                        }

                        return diskInfoList;
                    }

                    var options = new ConnectionOptions
                    {
                        Impersonation = ImpersonationLevel.Impersonate,
                        EnablePrivileges = false,
                        Authentication = AuthenticationLevel.Packet
                    };

                    var scopePath = $"\\\\{remoteName}\\root\\cimv2";
                    var scope = new ManagementScope(scopePath, options);

                    try
                    {
                        scope.Connect();

                        var testClass = new ManagementClass(scope, new ManagementPath("Win32_LogicalDisk"), null);
                        testClass.Get();
                    }
                    catch (ManagementException mex)
                    {
                        Console.WriteLine($"WMI class Win32_LogicalDisk not present on {remoteName}: {mex.Message}");
                        return new List<object>();
                    }

                    using (var searcher = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM Win32_LogicalDisk")))
                    {
                        foreach (ManagementObject drive in searcher.Get())
                        {
                            ProcessDriveInfo(drive, serverName, diskInfoList);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error getting disk space data: {ex.Message}");
                return new List<object>();
            }

            return diskInfoList;
        }

        private void ProcessDriveInfo(ManagementObject drive, string serverName, List<object> diskInfoList)
        {
            string deviceID = drive["DeviceID"]?.ToString();
            if (string.IsNullOrEmpty(deviceID)) return;

            var driveTypeObj = drive["DriveType"];
            if (driveTypeObj == null) return;

            int driveType = Convert.ToInt32(driveTypeObj);
            if (driveType != 3) return;

            ulong totalSize = 0;
            ulong freeSpace = 0;

            if (drive["Size"] != null)
                totalSize = Convert.ToUInt64(drive["Size"]);

            if (drive["FreeSpace"] != null)
                freeSpace = Convert.ToUInt64(drive["FreeSpace"]);

            string formattedTotalSize = FormatSize(totalSize);
            string formattedFreeSpace = FormatSize(freeSpace);

            double percentageUsed = totalSize > 0 ? (double)(totalSize - freeSpace) / totalSize * 100 : 0;

            diskInfoList.Add(new
            {
                ServerName = serverName,
                DriveLetter = deviceID,
                FormattedTotalSize = formattedTotalSize,
                FormattedFreeSpace = formattedFreeSpace,
                PercentageFree = Math.Round(100 - percentageUsed, 2),
                PercentageUsed = Math.Round(percentageUsed, 2)
            });
        }

        private string FormatSize(ulong sizeInBytes)
        {
            if (sizeInBytes > int.MaxValue)
            {
                double gb = sizeInBytes / 1073741824.0;
                return $"{gb:F2} GB";
            }
            else
            {
                return $"{sizeInBytes / 1024} MB";
            }
        }
    }
}
