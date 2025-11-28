# Fuzzing
## ffuf
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
# DNS
## Dig
### Zone Transfer
  ```bash
  dig axfr @<IP of DNS> <domain>
  # Example
  dig axfr @10.129.199.210 inlanefreight.local
  ```
