@echo off

:: Disable NetBIOS over TCP/IP
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" /v "NetBIOSOptions" /t REG_DWORD /d 0 /f

:: Enable Windows Firewall
netsh advfirewall set allprofiles state on

:: Configure Windows Firewall to block inbound traffic that does not correspond to an allowed outbound connection
netsh advfirewall set global statefulftp enable
netsh advfirewall set global statefulpptp enable
netsh advfirewall set global statefulicmp enable

:: Enable PowerShell script block logging
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockInvocationLogging" -Value 1

:: Disable SMBv1
sc.exe config lanmanworkstation depend= bowser/mrxsmb20/nsi
sc.exe config mrxsmb10 start= disabled

:: Enable User Account Control (UAC)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d 1 /f

:: Disable LM and NTLMv1 authentication
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "LMCompatibilityLevel" /t REG_DWORD /d 5 /f

:: Disable Anonymous Access to Named Pipes and Shares
reg add "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /v "RestrictNullSessAccess" /t REG_DWORD /d 1 /f

:: Set minimum password length to 14 characters
net accounts /minpwlen:14

:: Disable Remote Desktop Services
sc config "TermService" start= disabled

:: Disable the Guest account
net user guest /active:no

:: Set audit policy to log successful logon and logoff events
auditpol /set /subcategory:"Logoff" /success:enable /failure:disable
auditpol /set /subcategory:"Logon" /success:enable /failure:disable

:: Disable autorun for non-volume devices
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutoplayfornonVolume" /t REG_DWORD /d 1 /f

:: Disable all scheduled tasks that are not required
schtasks /query /fo LIST | findstr /i /c:"taskname:" /c:"next run time:" > tasklist.txt
FOR /F "tokens=2 delims=:" %%i in ('type tasklist.txt ^| find /c "TaskName:"') DO SET total=%%i
FOR /F "tokens=2 delims=:" %%i in ('type tasklist.txt ^| find /c /i "never"') DO SET never=%%i
set /a disabled=%total% - %never%
FOR /F "tokens=2 delims=:" %%i in ('type tasklist.txt ^| find /c /i "disabled"') DO SET enabled=%%i
FOR /F "tokens=2 delims=:" %%i in ('type tasklist.txt ^| find /c /i "ready"') DO SET ready=%%i
FOR /F "tokens=2 delims=:" %%i in ('type tasklist.txt ^| find /c /i "running"') DO SET running=%%i
FOR /F "tokens=2 delims=:" %%i in ('type tasklist.txt ^| find /c /i "queued"') DO SET queued=%%i

echo Total Tasks: %total%
echo Never Run: %never%
echo Enabled: %enabled%
echo Ready: %ready%
echo Running: %running%
echo Queued: %queued%

FOR /F "tokens=2 delims=:" %%i in ('type tasklist.txt ^| findstr /i /c:"taskname:"') DO schtasks /change /tn "%%i" /disable

:: Clear the event log files
wevtutil el | ForEach-Object {wevtutil cl "$_"}

:: Disable Windows Script Host
reg add "HKLM\Software\Microsoft\Windows Script Host\Settings" /v "Enabled" /t REG_DWORD /d 0 /f

:: Disable automatic proxy settings
reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "EnableAutoProxyResultCache" /t REG_DWORD /d 0 /f

:: Enable Windows Defender
Set-MpPreference -DisableRealtimeMonitoring 0

:: Enable Secure Boot
bcdedit /set {current} secureboot on

:: Disable guest access to the network
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "AllowInsecureGuestAuth" /t REG_DWORD /d 0 /f

:: Disable SMBv2 and SMBv3 compression
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "Smb2DisableCompression" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "DisableCompression" /t REG_DWORD /d 1 /f

:: Disable Remote Assistance
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fAllowToGetHelp" /t REG_DWORD /d 0 /f

:: Configure password complexity
net accounts /minpwlen:14 /maxpwage:60 /minpwage:1 /uniquepw:1 /passwordchg:1

:: Disable the built-in administrator account
net user administrator /active:no

:: Disable unencrypted traffic over LDAP and LDAPS
reg add "HKLM\System\CurrentControlSet\Services\LDAP\Parameters" /v "LDAPServerIntegrity" /t REG_DWORD /d 2 /f
reg add "HKLM\System\CurrentControlSet\Services\LDAP\Parameters" /v "LDAPClientIntegrity" /t REG_DWORD /d 2 /f

:: Disable DNS recursion
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DNS\Parameters" /v "EnableRecursion" /t REG_DWORD /d 0 /f

echo The hardening script has completed successfully!
pause
