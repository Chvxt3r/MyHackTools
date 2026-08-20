# Wordlist Generators (or links to them)

# HTB Wordlist generators
:warning: Some of these are pretty old.
|Link|Description|
|----|-----------|
|[Smart Password Generator](https://github.com/ahmdrz/wifi-password-generator)|Generates wordlist based on salt, MAC and BSSID of the target|
|[IMEI Password Generator](https://github.com/RealEnder/imeigen)|WPA-PSK default password candidates generator for mobile broadband WIFI routers, based on IMEI|
|[Time Warner/Spectrum Routers Cracker](https://github.com/datagoboom/twcracker)|Default Password Generator for Time Warner / Spectrum Routers|
|[Wifi-WPA-Keyspace-List](https://github.com/sheimo/Wifi-WPA-Keyspace-List)|A list of various routers default WPA key space|
|[Netgear-Password-Constructinator](https://github.com/redsquirrel7/Netgear-Password-Constructinator)| Netgear Password Generator

## Custom Wordlists
### Using Cewl
```bash
cewl -d <depth> -m <min_word_length> -w <output_file> <target_url>
```
* `-d`: Sets how deep CeWL should spider through the website’s links.
* `-m`: Sets the minimum length of the words to include (useful to align with password policies).
* `-w`: Defines the output file where the generated wordlist will be saved.
* `<target_url>`:  The URL of the website to scan.

### Crunch (Parameter Based Wordlists)
```bash
crunch <min_length> <max_length> <charset> -t <pattern> -o <output_file>
```
* `<min_length>` and `<max_length>`: Defines the minimum and maximum length of the generated passwords.
* `<charset>`: Defines which characters to include (e.g., lowercase, uppercase, digits, symbols).
* `-t <pattern>`: Specifies a pattern to follow when generating passwords.
* `-o <output_file>`: Saves the output to a specified file.

Pattern Placeholders (used with `-t`)
* `@` -> Lowercase letters (a–z)
* `,` -> Uppercase letters (A–Z)
* `%` -> Numbers (0–9)
* `^` -> Symbols (e.g., !, @, #)

```bash
# Generate an 8 character password list that starts with Ab and followed by 6 digits
crunch 8 8 0123456789 -t Ab%%%%%% -o number_passwords.txt
```

### CUPP (OSINT Based)
```bash
cupp [-h] [-i | -w FILENAME | -l | -a | -v] [-q]
```
* `-h`: Shows the help message and exit
* `-i`: Interactive questions for user password profiling
I `-w`: Use this option to improve existing dictionary, or WyD.pl output to make some pwnsauce
* `-l`: Download huge wordlists from repository
* `-a`: Parse default usernames and passwords directly from Alecto DB.
* `-v`: Shows the version of this program.
* `-q`: Runs cupp in quiet mode
