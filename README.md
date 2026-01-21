# MonitorService

This service captures SNMP hex data, decodes some of the hex into a readable format and saves it to a SQL Database (localhost\MONITORSERVICE). It runs a website to view SNMP in the database on https://localhost:8443

I built it to target Windows Server 2019 with .NET Framework 4.7.2 and SQL Server 2019 Express.

## Installation:
As a service, create a folder and run the following in Terminal as Administrator:
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe .\MonitorService.exe

When installing SQL Server, instance should be MONITORSERVICE and SYSTEM should be given sysadmin rights (this can be changed depending on the user that is running the service)

## Uninstall:
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /u .\MonitorService.exe

### To debug:
.\MonitorService.exe /debug (make sure the user running the service has sysadmin rights on MONITORSERVICE instance)