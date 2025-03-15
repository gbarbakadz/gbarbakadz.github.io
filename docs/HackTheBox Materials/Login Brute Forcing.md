
# Login Brute Forcing Cheat Sheet

## What is Brute Forcing?
A trial-and-error method used to crack passwords, login credentials, or encryption keys by systematically trying every possible combination of characters.

### Factors Influencing Brute Force Attacks
- Complexity of the password or key
- Computational power available to the attacker
- Security measures in place

## How Brute Forcing Works
1. **Start**: The attacker initiates the brute force process.
2. **Generate Possible Combination**: The software generates a potential password or key combination.
3. **Apply Combination**: The generated combination is attempted against the target system.
4. **Check if Successful**: The system evaluates the attempted combination.
5. **Access Granted (if successful)**: The attacker gains unauthorized access.
6. **End (if unsuccessful)**: The process repeats until the correct combination is found or the attacker gives up.

## Types of Brute Forcing

| Attack Type | Description | Best Used When |
|------------|-------------|----------------|
| **Simple Brute Force** | Tries every possible character combination in a set (e.g., lowercase, uppercase, numbers, symbols). | When there is no prior information about the password. |
| **Dictionary Attack** | Uses a pre-compiled list of common passwords. | When the password is likely weak or follows common patterns. |
| **Hybrid Attack** | Combines brute force and dictionary attacks, adding numbers or symbols to dictionary words. | When the target uses slightly modified versions of common passwords. |
| **Credential Stuffing** | Uses leaked credentials from other breaches to access different services where users may have reused passwords. | When you have a set of leaked credentials, and the target may reuse passwords. |
| **Password Spraying** | Attempts common passwords across many accounts to avoid detection. | When account lockout policies are in place. |
| **Rainbow Table Attack** | Uses precomputed tables of password hashes to reverse them into plaintext passwords. | When a large number of password hashes need cracking, and storage for tables is available. |
| **Reverse Brute Force** | Targets a known password against multiple usernames. | When there’s a suspicion of password reuse across multiple accounts. |
| **Distributed Brute Force** | Distributes brute force attempts across multiple machines to speed up the process. | When the password is highly complex, and a single machine isn't powerful enough. |

## Default Credentials

| Device | Username | Password |
|--------|----------|----------|
| Linksys Router | admin | admin |
| Netgear Router | admin | password |
| TP-Link Router | admin | admin |
| Cisco Router | cisco | cisco |
| Ubiquiti UniFi AP | ubnt | ubnt |

## Brute-Forcing Tools

### Hydra
- Fast network login cracker
- Supports numerous protocols
- Uses parallel connections for speed
- Flexible and adaptable
- Relatively easy to use

**Example Usage:**
```sh
hydra [-l LOGIN|-L FILE] [-p PASS|-P FILE] [-C FILE] -m MODULE [service://server[:PORT][/OPT]]
```
#### Hydra Examples

| Service/Protocol | Description | Example Command |
|-----------------|-------------|-----------------|
| **FTP** | Used to brute-force login credentials for FTP services. | `hydra -l admin -P /path/to/password_list.txt ftp://192.168.1.100` |
| **SSH** | Targets SSH services to brute-force credentials. | `hydra -l root -P /path/to/password_list.txt ssh://192.168.1.100` |
| **HTTP GET/POST** | Used to brute-force web login forms using GET/POST requests. | `hydra -l admin -P /path/to/password_list.txt 127.0.0.1 http-post-form "/login.php:user=^USER^&pass=^PASS^:F=incorrect"` |

### Medusa
- Fast, massively parallel, modular login brute-forcer
- Supports a wide array of services

**Example Usage:**
```sh
medusa [-h host|-H file] [-u username|-U file] [-p password|-P file] [-C file] -M module [OPT]
```
#### Medusa Examples

| Service/Protocol | Description | Example Command |
|-----------------|-------------|-----------------|
| **SSH** | Brute force SSH login for the admin user. | `medusa -h 192.168.1.100 -u admin -P passwords.txt -M ssh` |
| **FTP** | Brute force FTP with multiple usernames and passwords. | `medusa -h 192.168.1.100 -U users.txt -P passwords.txt -M ftp -t 5` |
| **RDP** | Brute force RDP login. | `medusa -h 192.168.1.100 -u admin -P passwords.txt -M rdp` |
| **HTTP Basic Auth** | Brute force HTTP Basic Authentication. | `medusa -h www.example.com -U users.txt -P passwords.txt -M http -m GET` |

## Custom Wordlists

### Username Anarchy
Generates potential usernames based on a target's name.

**Example Commands:**
```sh
username-anarchy "Jane Smith"  # Generate usernames for "Jane Smith"
username-anarchy -i names.txt  # Use a file (names.txt) for input
username-anarchy -a --country us  # Generate usernames using US dataset
username-anarchy -@ example.com  # Append @example.com as a suffix
```

### CUPP (Common User Passwords Profiler)
Creates personalized password wordlists based on gathered intelligence.

**Example Commands:**
```sh
cupp -i  # Generate wordlist interactively
cupp -w profiles.txt  # Generate a wordlist from a predefined profile file
cupp -l  # Download popular password lists like rockyou.txt
```

## Password Policy Filtering

### Common `grep` Patterns for Filtering Wordlists

| Policy Requirement | `grep` Regex Pattern | Explanation |
|-------------------|--------------------|-------------|
| Minimum Length (8 chars) | `grep -E '^.{8,}$' wordlist.txt` | Ensures at least 8 characters per line. |
| At Least One Uppercase Letter | `grep -E '[A-Z]' wordlist.txt` | Matches any uppercase letter. |
| At Least One Lowercase Letter | `grep -E '[a-z]' wordlist.txt` | Matches any lowercase letter. |
| At Least One Digit | `grep -E '[0-9]' wordlist.txt` | Matches any numeric digit. |
| At Least One Special Character | `grep -E '[!@#$%^&*()_+-=[]{};':"\,.<>/?]' wordlist.txt` | Matches any special character. |
| No Consecutive Repeated Characters | `grep -E '(.)' wordlist.txt` | Detects repeated characters. Use `grep -v` to exclude matches. |
| Exclude "password" | `grep -v -i 'password' wordlist.txt` | Case-insensitive exclusion of the word "password". |
| Exclude Dictionary Words | `grep -v -f dictionary.txt wordlist.txt` | Removes common dictionary words from the list. |

