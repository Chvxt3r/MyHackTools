# Ffuf
- Copy the POST request out of burp into a file.
- Edit the POST request and replace the username and password with USERFUZZ and PASSFUZZ
```
ffuf -request [filename.txt] -request-proto [http/https] -mode clusterbomb -w [userlist.txt]:USERFUZZ -w [passwordlist.txt]:PASSFUZZ [-fs/-ms/-fw]
```
