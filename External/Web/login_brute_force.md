# Ffuf
- Copy the POST request out of burp into a file.
- Edit the POST request and replace the username and password with USERFUZZ and PASSFUZZ
```
ffuf -request [filename.txt] -request-proto [http/https] -mode clusterbomb -w [userlist.txt]:USERFUZZ -w [passwordlist.txt]:PASSFUZZ [-fs/-ms/-fw]

# Command that acutally worked for PNPT
fuf -request req.txt -request-proto https -mode clusterbomb -w tools/wordlists/common-passwords.txt:PASSFUZZ -mc 303 -v -fr "INVALID_CREDENTIALS"
```
