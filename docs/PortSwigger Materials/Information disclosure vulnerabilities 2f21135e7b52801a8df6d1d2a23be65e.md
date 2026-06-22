# Information disclosure vulnerabilities

## **Common sources of information disclosure**

The following are some common examples of places where sensitive information is exposed. 

- **Files for web crawlers**
- **Directory listings**
- **Developer comments**
- **Developer comments**
- **Error messages**
- **Debugging data**
- **User account pages**
- **Source code disclosure via backup files**
- **Information disclosure due to insecure configuration**
- **Version control history**

Information disclosure vulnerabilities can arise in  countless different ways, but these can broadly be categorized as  follows:

- **Failure to remove internal content from public content**. For example, developer comments in markup are sometimes visible to users in the production environment.
- **Insecure configuration of the website and related technologies**. For example, failing to disable debugging and diagnostic features can sometimes provide attackers with useful tools to help them obtain sensitive information. Default configurations can also leave websites
vulnerable, for example, by displaying overly verbose error messages.
- **Flawed design and behavior of the application**. For example, if a website returns distinct responses when different error states occur, this can also allow attackers to [enumerate sensitive data](https://portswigger.net/web-security/authentication/password-based#username-enumeration), such as valid user credentials.

## Labs

[**Information disclosure in error messages**](https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-in-error-messages)

`Unexpected data type exposes Framework Version`

[**Information disclosure on debug page**](https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-on-debug-page)

**`*/cgi/bin/phpinfo.php*** exposes SECRET_KEY`

[**Source code disclosure via backup files**](https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-via-backup-files)

`robots.txt file exposes backup file location, leading to getting credentials`

[**Authentication bypass via information disclosure**](https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-authentication-bypass)

`TRACE method exposes custom HTTP header, which bypass authentication mechanism`

[**Information disclosure in version control history**](https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-in-version-control-history)

`Git logs exposes hardcoded credentials`