# MonitorService

This service captures SNMP hex data, decodes some of the hex into a readable format and saves it to a SQL Database (localhost\MONITORSERVICE). It runs a website to view Disk Space of added Servers and SNMP data on https://localhost:8443

I built it to target Windows Server 2019 with .NET Framework 4.7.2 and SQL Server 2019 Express. Purpose is to not rely on any external packages.

## Installation:
As a service, create a folder and run the following in Terminal as Administrator:
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe .\MonitorService.exe

When installing SQL Server, instance should be MONITORSERVICE. The service account should be given sysadmin rights on the MONITORSERVICE instance. The service account running the MonitorService should also have admin rights on the servers being monitored to get Disk Space information.

## Uninstall:
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /u .\MonitorService.exe

### To debug:
.\MonitorService.exe /debug (make sure the user running this command has sysadmin rights on MONITORSERVICE instance)