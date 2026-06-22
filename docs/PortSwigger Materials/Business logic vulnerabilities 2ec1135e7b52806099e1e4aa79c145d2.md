# Business logic vulnerabilities

## **Excessive trust in client-side controls**

A fundamentally flawed assumption is that users will only interact with the application via the provided web interface. This is especially dangerous because it leads to the further assumption that client-side validation will prevent users from supplying malicious input. However, an attacker can simply use tools such as Burp Proxy to tamper with the data after it has been sent by the browser but before it is passed into the server-side logic. This effectively renders the client-side controls useless.

## **Failing to handle unconventional input**

When auditing an application, you should use tools such as Burp Proxy and Repeater to try submitting unconventional values. In  particular, try input in ranges that legitimate users are unlikely to ever enter. This includes exceptionally high or exceptionally low numeric inputs and abnormally long strings for text-based fields. You can even try unexpected data types. By observing the application's response, you should try and answer the following questions:

- Are there any limits that are imposed on the data?
- What happens when you reach those limits?
- Is any transformation or normalization being performed on your input?

**Example**:  Numeric data type might accept negative values. Depending on the related functionality, it may not make sense for the business logic to allow this. However, if the application doesn't perform adequate server-side validation and reject this input, an attacker may be able to pass in a negative value and induce unwanted behavior. 

## **Making flawed assumptions about user behavior**

When probing for logic flaws, you should try removing each  parameter in turn and observing what effect this has on the response.  You should make sure to:

- Only remove one parameter at a time to ensure all relevant code paths are reached.
- Try deleting the name of the parameter as well as the value. The server will typically handle both cases differently.
- Follow multi-stage processes through to completion. Sometimes tampering with a parameter in one step will have an effect on another step further along in the workflow.

Submit requests in an unintended sequence. For example, skip certain steps, access a single step more than once, return to earlier steps, and so on. Take note of how different steps are accessed.  Although  often just submit a `GET` or `POST` request to a specific URL, sometimes can access steps by submitting different sets of parameters to the same URL

## **Domain-specific flaws**

The discounting functionality of online shops is a classic attack surface when hunting for logic flaws. This can be a potential gold mine for an attacker, with all kinds of basic logic flaws occurring in the way discounts are applied.

For example, consider an online shop that offers a 10% discount on orders over $1000. This could be vulnerable to abuse if the business logic fails to check whether the order was changed after the discount is applied. In this case, an attacker could simply add items to their cart until they hit the $1000 threshold, then remove the items they don't want before placing the order. They would then receive the discount on their order even though it no longer satisfies the intended criteria.

## **Providing an encryption oracle**

Dangerous scenarios can occur when user-controllable input is encrypted and the resulting ciphertext is then made available to the user in some way. This kind of input is sometimes known as an "encryption oracle". An attacker can use this input to encrypt arbitrary data using the correct algorithm and asymmetric key. 

## **Email address parser discrepancies**

Some websites parse email addresses to extract the domain and determine which organization the email owner belongs to. While this process may initially seem straightforward, it is actually very complex, even for valid RFC-compliant addresses. 

## Labs

### **Excessive trust in client-side controls**

[**Excessive trust in client-side controls**](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-excessive-trust-in-client-side-controls)

`productId=1&redir=PRODUCT&quantity=1&price=[modify price to Buy at low price]` 

[**2FA broken logic**](https://0a83002004dd5c4c81b35c45002400c3.web-security-academy.net/my-account)

`Change session verify parameter to victim user. Brute force generated 2FA code`

### **Failing to handle unconventional input**

[**High-level logic vulnerability**](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-high-level)

`Add two items to checkout. Change one of the item quantity with negative integer. Note that price is changing to low after each Request with negative integer.` 

[**Low-level logic flaw**](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-low-level)

`Increase the item quantity till price gets the negative value. Then continue increasing for the lowest price.`

[**Inconsistent handling of exceptional input**](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-inconsistent-handling-of-exceptional-input)

`Set very-long-string@dontwannacry.com.YOUR-EMAIL-ID.web-security-academy.net email in Registration. Note that only 255 characters of email is displayed, so craft email where @dontwannacry.com will be the last characters in 255 byte long words.`

### **Making flawed assumptions about user behavior**

[**Inconsistent security controls**](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-inconsistent-security-controls)

`Login and change Email to desired one`

[**Weak isolation on dual-use endpoint**](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-weak-isolation-on-dual-use-endpoint)

`Login and change the password by setting username to an arbitrary user and removing current-password parameter.` 

[**Password reset broken logic**](https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-reset-broken-logic)

`IDOR on Change Password function`

[**2FA simple bypass**](https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-simple-bypass)

`Drop MFA request`

[**Insufficient workflow validation**](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-insufficient-workflow-validation)

`Buy low-priced item and save confirmation request. Add high-priced item to cart and send saved confirmation request. Note that the flow bypass restrictions of checking balance.`

[**Authentication bypass via flawed state machine**](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-authentication-bypass-via-flawed-state-machine)

`During the login process, Drop the role-selector request which leading to administrative access on the application`

### **Domain-specific flaws**

[**Flawed enforcement of business rules**](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-flawed-enforcement-of-business-rules)

`Use two different coupons in sequence to bypass same coupon validation`

[**Infinite money logic flaw**](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-infinite-money)

`Gift Card > SIGNUP Coupon > Checkout = 3$ profit on each request`

### **Providing an encryption oracle**

[**Authentication bypass via encryption oracle**](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-authentication-bypass-via-encryption-oracle)

`Encryption - POST /post/comment and Decryption in the subsequent GET /post?postId=x`

### **Email address parser discrepancies**

[**Bypassing access controls using email address parsing discrepancies**](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-bypassing-access-controls-using-email-address-parsing-discrepancies)