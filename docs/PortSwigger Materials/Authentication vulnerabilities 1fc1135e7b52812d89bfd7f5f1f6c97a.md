# Authentication vulnerabilities

### What is the difference between authentication and authorization?

> NOTE Authentication is the process of verifying that a user is who they claim to be. Authorization involves verifying whether a user is allowed to do something.
> 

## Vulnerabilities in password-based login

### Username enumeration

- **Status codes**
- **Error messages**
- **Response times**

### Flawed brute-force protection

Sometimes IP is blocked if you fail to log in too many times. In some implementations, the counter for the number of failed attempts resets if the IP owner logs in successfully. This means an attacker would simply have to log in to their own account every few attempts to prevent this limit from ever being reached

### Account locking

Responses from the server indicating that an account is locked can also help an attacker to enumerate usernames. 

### User rate limiting

Making too many login requests within a short period of time causes  your IP address to be blocked. Typically, the IP can only be unblocked in one of the following ways:

- Automatically after a certain period of time has elapsed
- Manually by an administrator
- Manually by the user after successfully completing a CAPTCHA

As the limit is based on the rate of HTTP requests sent from the user’s IP address, it is sometimes also possible to bypass this defense if you can work out how to guess multiple passwords with a single request.

### HTTP basic authentication

```markdown
Authorization: Basic base64(username:password)

Vulnerable to - MITM / CSRF / Brute Forcing
```

## Vulnerabilities in multi-factor authentication

### Bypassing two-factor authentication

If the user is first prompted to enter a password, and then prompted to enter a verification code on a separate page, the user is effectively in a “logged in” state before they have entered the verification code. In this case, it is worth testing to see if you can directly skip to “logged-in only” pages after completing the first authentication step. Occasionally, you will find that a website doesn’t actually check whether or not you completed the second step before loading the page.

### Flawed two-factor verification logic

Sometimes flawed logic in two-factor authentication means that after a user has completed the initial login step, the website doesn’t adequately verify that the same user is completing the second step.

### **Brute-forcing 2FA verification codes**

Some websites attempt to prevent brute-force attack by automatically logging a user out if they enter a certain number of incorrect verification codes. This is ineffective in practice because an advanced attacker can even  automate this multi-step process by [creating macros](https://portswigger.net/burp/documentation/desktop/settings/sessions#macros) for Burp Intruder

## Vulnerabilities in other authentication mechanisms

### Keeping users logged in

Brute-force other users’ cookies (Remember Me Cookies) to gain access to their accounts.

### Resetting user passwords

Some websites fail to validate the token again when the reset form is submitted. In this case, an attacker could simply visit the reset form from their own account, delete the token, and leverage this page to reset an arbitrary user’s password by changing *username* parameter to target user

### Changing user passwords

Password change functionality can be particularly dangerous if it allows an attacker to access it directly without being logged in as the victim user. For example, if the username is provided in a hidden field, an attacker might be able to edit this value in the request to target arbitrary users. This can potentially be exploited to enumerate usernames and brute-force passwords.

## Labs

[Username enumeration via different responses](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-different-responses)

`Different Status Codes`

[Username enumeration via subtly different responses](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-subtly-different-responses)

`Grep - Extract - invalid username or password.`

[Username enumeration via response timing](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-response-timing)

`X-Forwarded-For - IP Restriction Bypass
Set Password with high number characters (at least 100)
Response Recieved and Response Completed filters should be significantly HIGH`

[Broken brute-force protection, IP block](https://portswigger.net/web-security/authentication/password-based/lab-broken-bruteforce-protection-ip-block)

`Use Macro to send Login/Logout requests, that will reset lockout attempts.
Set Intruder Resource Pool concurrent threads to 1.`

[Username enumeration via account lock](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-account-lock)

`Lock accounts to determine valid usernames
Use Sniper intruder with Grep - Extract - invalid username or password.`

[2FA simple bypass](https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-simple-bypass)

`Drop MFA request`

[2FA broken logic](https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-broken-logic)

`Change session verify parameter to victim user. Brute force generated 2FA code`

[2FA bypass using a brute-force attack](https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-bypass-using-a-brute-force-attack)

`Create Macro > Configure not to update mfa-code parameter > Run Intruder`

[Brute-forcing a stay-logged-in cookie](https://portswigger.net/web-security/authentication/other-mechanisms/lab-brute-forcing-a-stay-logged-in-cookie)

`Brute Force Stay-Logged-In cookie, that is easyly guessable`

[Offline password cracking](https://portswigger.net/web-security/authentication/other-mechanisms/lab-offline-password-cracking)

`Steal Cookie with Stored XSS and Brute Force using CrackStation`

[Password reset broken logic](https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-reset-broken-logic)

`IDOR on Change Password function`

[Password reset poisoning via middleware](https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-reset-poisoning-via-middleware)

`X-Forwarded-Host Abuse to steal token`

[Password brute-force via password change](https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-brute-force-via-password-change)

`Change username parameter with Target user and Brute-Force *current-password* parameter to get the password`

[Broken brute-force protection, multiple credentials per request](https://portswigger.net/web-security/authentication/password-based/lab-broken-brute-force-protection-multiple-credentials-per-request)

```json
{
  "username": "carlos",
  "password": [
    "123456",
    "password",
    "password2"
    ...
  ]
}
```