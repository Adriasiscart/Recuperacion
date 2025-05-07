$script = @"
@echo off
REM ---------------------------------------------------------
REM Script automatitzat per Windows Server Core
REM Configura DNS, DHCP, SSH, NFS, FTPS, Firewall i backups
REM ---------------------------------------------------------

echo Iniciant configuració del servidor...
echo Iniciant instal·lació > C:\setup-log.txt

set /p change_ip="Voleu canviar la IP del servidor a 192.168.1.30 (S/N)? "
if /I "%change_ip%"=="S" (
    echo Configurant IP estàtica...
    netsh interface ip set address name="Ethernet" static 192.168.1.30 255.255.255.0 192.168.1.1
    echo IP del servidor configurada a 192.168.1.30 >> C:\setup-log.txt
) else (
    echo IP no modificada >> C:\setup-log.txt
)

set /p dns_domain="Introduïu el nom de domini DNS (ex: empresa.local): "

powershell -Command "Install-WindowsFeature DNS -IncludeManagementTools"
powershell -Command "Install-WindowsFeature RSAT-DNS-Server"
powershell -Command "Install-WindowsFeature DHCP -IncludeManagementTools"
powershell -Command "Install-WindowsFeature FS-NFS-Service"
powershell -Command "Install-WindowsFeature OpenSSH.Server"

net start DNS
sc config DNS start= auto
net start dhcpserver
sc config dhcpserver start= auto
net start sshd
sc config sshd start= auto
net start NfsService
sc config NfsService start= auto

echo Configurant DNS...
dnscmd /zoneadd %dns_domain% /primary
dnscmd /recordadd %dns_domain% server1 A 192.168.1.30
echo DNS configurat >> C:\setup-log.txt

set /p dhcp_scope_start="Inici rang DHCP (ex: 192.168.1.100): "
set /p dhcp_scope_end="Fi rang DHCP (ex: 192.168.1.200): "
set /p dhcp_subnet="Màscara de subxarxa (ex: 255.255.255.0): "

REM Obtenir la IP de xarxa a partir de l’inici del rang (assumim /24)
for /f "tokens=1-3 delims=." %%a in ("%dhcp_scope_start%") do set ScopeID=%%a.%%b.%%c.0

REM Crear àmbit i definir rang
netsh dhcp server 192.168.1.30 add scope %ScopeID% %dhcp_subnet% "Scope1"
netsh dhcp server 192.168.1.30 scope %ScopeID% add iprange %dhcp_scope_start% %dhcp_scope_end%
echo DHCP configurat >> C:\setup-log.txt

mkdir C:\NFS-Share
nfsadmin server addshare NFSPublic=C:\NFS-Share anon=yes
echo NFS activat i compartit a C:\NFS-Share >> C:\setup-log.txt

REM Firewall Rules
netsh advfirewall firewall add rule name="Allow DNS" dir=in action=allow protocol=UDP localport=53
netsh advfirewall firewall add rule name="Allow DHCP" dir=in action=allow protocol=UDP localport=67
netsh advfirewall firewall add rule name="Allow NFS" dir=in action=allow protocol=TCP localport=2049
netsh advfirewall firewall add rule name="Allow SSH" dir=in action=allow protocol=TCP localport=22

REM Backup
echo Programant còpia de seguretat diària...
mkdir C:\Backups
schtasks /create /tn "BackupDiari" /tr "wbadmin start backup -backupTarget:C:\Backups -include:C: -allCritical -quiet" /sc daily /st 03:00 /ru SYSTEM
echo Backup programat >> C:\setup-log.txt

REM Actualitzacions
powershell -Command "Install-WindowsUpdate -AcceptAll -AutoReboot"

REM Informació DNS
echo Detalls de la configuració DNS: >> C:\setup-log.txt
echo Zona DNS: %dns_domain% >> C:\setup-log.txt
echo Nom del servidor: server1.%dns_domain% >> C:\setup-log.txt
echo IP associada: 192.168.1.30 >> C:\setup-log.txt

REM FTPS
echo Configurant FTP amb SSL (FTPS)...

set /p ftps_user="Introdueix nom d'usuari per FTPS: "
:password_prompt
set /p ftps_pass="Introdueix contrasenya per FTPS (mín. 8 caràcters, 1 majúscula, 1 número, 1 símbol): "
echo %ftps_pass% | findstr /R ".*[A-Z].*" >nul || goto password_invalid
echo %ftps_pass% | findstr /R ".*[0-9].*" >nul || goto password_invalid
echo %ftps_pass% | findstr /R ".*[^A-Za-z0-9].*" >nul || goto password_invalid
if not "%ftps_pass:~7,1%"=="" goto password_ok
:password_invalid
echo Contrasenya no vàlida. Torna-ho a provar.
goto password_prompt
:password_ok

set /p ftps_mode="Vols permetre també FTP sense SSL? (S/N): "

echo Instal·lant components FTPS...
powershell -Command "Install-WindowsFeature Web-Server, Web-Ftp-Server, Web-Ftp-Service, Web-Mgmt-Console"

mkdir C:\FTP-Share 2>nul

powershell -Command "net user %ftps_user% '%ftps_pass%' /add"
powershell -Command "net localgroup 'Users' %ftps_user% /add"
powershell -Command "icacls C:\FTP-Share /grant '%ftps_user%:(OI)(CI)F' /T"

powershell -Command "New-SelfSignedCertificate -CertStoreLocation 'Cert:\LocalMachine\My' -DnsName 'ftp.local'"

for /f "delims=" %%i in ('powershell -Command "(Get-ChildItem -Path 'Cert:\LocalMachine\My' | Where-Object { \$_.Subject -like '*ftp.local*' } | Select-Object -First 1).Thumbprint"') do set FTPCERT=%%i

echo Import-Module WebAdministration; > C:\temp_ftps_config.ps1
echo New-WebFtpSite -Name 'FTPSite' -Port 21 -PhysicalPath 'C:\FTP-Share' -Force -Ssl; >> C:\temp_ftps_config.ps1
echo Set-ItemProperty 'IIS:\Sites\FTPSite' -Name ftpServer.security.ssl.serverCertHash -Value '%FTPCERT%'; >> C:\temp_ftps_config.ps1
echo Set-ItemProperty 'IIS:\Sites\FTPSite' -Name ftpServer.firewallSupport.passivePortRange -Value '1025-1040'; >> C:\temp_ftps_config.ps1
if /I "%ftps_mode%"=="S" (
    echo Set-ItemProperty 'IIS:\Sites\FTPSite' -Name ftpServer.security.ssl.controlChannelPolicy -Value 1; >> C:\temp_ftps_config.ps1
    echo Set-ItemProperty 'IIS:\Sites\FTPSite' -Name ftpServer.security.ssl.dataChannelPolicy -Value 1; >> C:\temp_ftps_config.ps1
) else (
    echo Set-ItemProperty 'IIS:\Sites\FTPSite' -Name ftpServer.security.ssl.controlChannelPolicy -Value 2; >> C:\temp_ftps_config.ps1
    echo Set-ItemProperty 'IIS:\Sites\FTPSite' -Name ftpServer.security.ssl.dataChannelPolicy -Value 2; >> C:\temp_ftps_config.ps1
)
powershell -ExecutionPolicy Bypass -File C:\temp_ftps_config.ps1
del C:\temp_ftps_config.ps1

netsh advfirewall firewall add rule name="Allow FTP" dir=in action=allow protocol=TCP localport=21
netsh advfirewall firewall add rule name="Allow FTPS Passive Ports" dir=in action=allow protocol=TCP localport=1025-1040

echo FTPS configurat amb usuari %ftps_user% >> C:\setup-log.txt

REM Fi
echo Configuració finalitzada. Reiniciant en 10 segons...
echo Configuració finalitzada >> C:\setup-log.txt
shutdown /r /t 10

pause
exit
"@

Set-Content -Path "C:\setup-server.bat" -Value $script -Encoding UTF8
