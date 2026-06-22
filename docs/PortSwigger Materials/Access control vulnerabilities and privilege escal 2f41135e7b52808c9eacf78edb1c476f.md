# Access control vulnerabilities and privilege escalation

## What is access control?

Access control is the application of constraints on who or what is authorized to perform actions or access resources. In the context of web applications, access control is dependent on authentication and session management:

- **Authentication** confirms that the user is who they say they are.
- **Session management** identifies which subsequent HTTP requests are being made by that same user.
- **Access control** determines whether the user is allowed to carry out the action that they are attempting to perform.

### Vertical access controls

Vertical access controls are mechanisms that restrict access to sensitive functionality to specific types of users.

With vertical access controls, different types of users have access to different application functions. For example, an administrator might be able to modify or delete any user's account, while an ordinary user has no access to these actions. Vertical access controls can be more fine-grained implementations of security models designed to enforce business policies such as separation of duties and least privilege.

### Horizontal access controls

Horizontal access controls are mechanisms that restrict access to resources to specific users.

With horizontal access controls, different users have access to a subset of resources of the same type. For example, a banking application will allow a user to view transactions and make payments from their own accounts, but not the accounts of any other user.

### Context-dependent access controls

Context-dependent access controls restrict access to functionality and resources based upon the state of the application or the user's interaction with it.

Context-dependent access controls prevent a user performing actions in the wrong order. For example, a retail website might prevent users from modifying the contents of their shopping cart after they have made payment.

## **Examples of broken access controls**

### **Vertical privilege escalation**

- **Unprotected functionality**
    - Source code might disclosure custom pages
- **Parameter-based access control**
    - Modifying parameters might lead to access resource
- **Platform misconfiguration**
    - Different request methods (GET/POST/PATCH…) and custom headers might lead to access resource
- **URL-matching discrepancies**
    - Passing Case-Sensitive URL address might bypass the restrictions. For example pass (ADMIN, instead of admin)

### **Horizontal privilege escalation**

- **Insecure direct object references**
    - Modifying parameters by setting another value

### **Access control vulnerabilities in multi-step processes**

- Access to the resource might be restricted, while subsequent requests might not be

### **Referer-based access control**

- Modifying Referer header might allow access to the resource

### **Location-based access control**

- Changing location via VPN might allow access to the resource

## Labs

[**Unprotected admin functionality**](https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality)

`Robots.txt exposes custom Administration page`

[**Unprotected admin functionality with unpredictable URL**](https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality-with-unpredictable-url)

`Source code exposes Javascript code, containing custom Administration page`

[**User role controlled by request parameter**](https://portswigger.net/web-security/access-control/lab-user-role-controlled-by-request-parameter)

`Cookie contains *Admin=false* parameter. Modify it to true value in order to get administrative privileges`

[**User role can be modified in user profile**](https://portswigger.net/web-security/access-control/lab-user-role-can-be-modified-in-user-profile)

`Modify low-privileged user Email. Note that response contains *roleid* parameter. Craft the Email Submission request with *roleid=2 parameter* to get Administrative privileges`.

[**User ID controlled by request parameter**](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter)

`Modify URL from */my-account?id=wiener* to */my-account?id=[arbitrary user]* to get an API key of victim user.`

[**User ID controlled by request parameter, with unpredictable user IDs**](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-unpredictable-user-ids)

`Blogs contain users with GUID values. Find the blog, owned by Carlos to retrieve GUID and pass to */my-account?id=[GUID of arbitrary user]*`

[**User ID controlled by request parameter with data leakage in redirect**](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-data-leakage-in-redirect)

`*/my-account?id=[arbitrary user]* redirects to /login page but leaks the page containing API key` 

[**User ID controlled by request parameter with password disclosure**](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-password-disclosure)

`User password is masked but can be retrieved through page source`

[**Insecure direct object references**](https://portswigger.net/web-security/access-control/lab-insecure-direct-object-references)

`IDOR in  /download-transcript/[id].txt`

[**URL-based access control can be circumvented**](https://portswigger.net/web-security/access-control/lab-url-based-access-control-can-be-circumvented)

`The application supports *X-Original-URL* Header, so the */admin* page can be bypassed using *X-Original-URL: /admin.* To delete user send GET /?username=carlos request alongside *X-Original-URL: /admin* header`

[**Method-based access control can be circumvented**](https://portswigger.net/web-security/access-control/lab-method-based-access-control-can-be-circumvented)

`POST method is forbidden while GET method bypass access controls to the resource`

[**Multi-step process with no access control on one step**](https://portswigger.net/web-security/access-control/lab-multi-step-process-with-no-access-control-on-one-step)
`Setting the user permission is forbidden, while the subsequent request is allowed and can be used unauthorized user`

[**Referer-based access control](https://portswigger.net/web-security/access-control/lab-referer-based-access-control)**
`Accessing the */admin* page can be bypassed by setting *Referer: [website]/admin*` `header`