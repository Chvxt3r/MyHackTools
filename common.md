# Common Tools
The most common tools I use, mostly for recon.

## Host Scans
### nmap
* My Initial Scan
  ```bash
  nmap -sCV -p- <$IP> --open -oA scans/nmap_initial
  ```

## Searches from Linux
### Grep
* Search recursively the contents of files
  ```bash
  grep -R "<search term>" <PATH>
  ```
* Search a file for any IP addresses
  ```bash
  grep -oE '((1?[0-9][0-9]?|2[0-4][0-9]|25[0-5])\.){3}(1?[0-9][0-9]?|2[0-4][0-9]|25[0-5])' FILE
  ```
### Credential Hunting
* Search config file for credentials
  ```bash
  cat wp-config.php | grep 'DB_USER\|DB_PASSWORD' # Use on any config files you find in /var
  ```
## Time Tools
### Faketime
> Useful for kerberos when your time is off  

Install libfaketime
* Sync your time with a destination time server for once command only
  ```bash
  faketime "$(ntpdate -q <ip of timesource> | cut -d'' -f 1,2)" <command>
  ```
* Add a set amount of time to your command
  ```bash
  faketime -f '+7h' <command>
  ```
## Fuzzing
### ffuf
* Fuzz directories
  ```bash
  ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt:FUZZ -u http://<Domain or IP>/FUZZ -ac
  ```
* Fuzz Subdomains
  ```bash
  ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://<Domain or IP> -H "Host:FUZZ.<Domain or IP" -ac
  ```
* Fuzz Extensions
  ```bash
  ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://SERVER_IP:PORT/blog/indexFUZZ
  ```
* Fuzz Files
  ```bash
  ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files.txt -u http://<Domain or IP>/FUZZ -e .php,.html,.txt -ac
  ```
* Fuzz Parameters(GET requests)
  ```bash
  ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:51480/admin/admin.php\?FUZZ\=key -ac
  ```
* Fuzz Parameters(POST)
  ```bash
  ffuf -w //usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:51480/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -ac
  ```
* Fuzz Values(POST)
  ```bash
  ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:51480/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -ac
  ```
## DNS
* Zone Transfer
  ```bash
  dig axfr @<IP of DNS> <domain>
  # Example
  dig axfr @10.129.199.210 inlanefreight.local
  ```
## Databases
### MySQL
* Connect to a MySQL instance
  ```bash
  mysql -u <user> -p<pass> -h <host> <db>#No space between -p and the password (ex: -pPassword)
  ```
