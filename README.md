# MonitorService

This service captures SNMP hex data and saves it to a text file in the same location as the executable.

I built it to target Windows Server 2019 with .NET Framework 4.7.2.

Installation:
As a service, create a folder and run the following in Terminal as Administrator:
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe .\MonitorService.exe

Uninstall:
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /u .\MonitorService.exe

To debug:
.\MonitorService.exe /debug