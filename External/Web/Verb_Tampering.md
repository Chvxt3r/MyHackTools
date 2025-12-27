# HTTP Verb Tampering
## Intro
### Verbs
HTTP has 9 different verbs that can be accepted as HTTP methods  

Commonly Used Verbs, other than `GET` and `POST`:
|Verb|Description|
|----|-----------|
|`HEAD`|Identical to a `GET` request, but its response only contains the headers, without the response body|
|`PUT`|Writes the request payload to the specified location|
|`DELETE`|Deletes the resource at the specified location|
|`OPTIONS`|Shows different options accepted by a web server, like accepted HTTP verbs|
|`PATCH`|Apply partial modifications to the resource at the specified location|

### Insecure Configurations
Example config:
```xml
<Limit GET POST>
    Require valid-user
</Limit>
```
In the above, even though the admin limits `GET` and `POST` to valid users, you may be able to use another method (like `HEAD`) to get the same result.

### Insecure Coding
Example Code:
```php
$pattern = "/^[A-Za-z\s]+$/";

if(preg_match($pattern, $_GET["code"])) {
    $query = "Select * from ports where port_code like '%" . $_REQUEST["code"] . "%'";
    ...SNIP...
}
```
In the above example, the sanitization check is only being performed on the `GET` request `if(preg_match($pattern, $_GET["code"])) {`. However, the actual query (`$query`) is built using the `$_REQUEST["code"]` parameters. This will allow a `POST` request to bypass the sanitization check. 

## Bypassing Basic Authentication
### Identification
- Look for `401 Unauthorized` page or HTTP basic auth prompt.
- Identify the URL the button or function points to.
- Determine whether it's the page or the folder that is restricted. (ie: is `admin/reset.php` restricted or is the entire admin folder?)
    - Visit just the folder, and see if you get a basic auth prompt. Example: visit `http://www.example.com/admin` and see if you get a prompt.

### Exploitation
- Analyze the page in burp and to determine what kind of request is being sent. (`GET`, `POST`, etc.)
- Try a different request type.
    - Check which verbs are available on the server.
    ```
    curl -i -X OPTION http://[server]:[port]/
    ```
    - In burp, either right-click the request and select `Change Request Method` or send to repeater and change manually.
    - For `GET` requests in particular, try using `HEAD`.
        - No output from `HEAD`, but may still trigger the functionality.
- See if we still get an auth prompt.

## Bypassing Security Filters
Insecure Coding is the most common type of Verb Tampering. Most commonly found in security filters that only process one type of request, and leave the other requests open.

### Identification
- Try and use special characters in the functionality and see if they are removed. Example file upload function: `test;!`.
    - See if the special characters are removed or the functionality is just blocked

### Exploitation
- Intercept the request in burp and change the verb.
- See if the functionality works even with the special character (It may just strip the special characters)
- Check and see if the function even works, if it does, we may have Command Execution on the server.
- Using our file manager example, we can try and add 2 files.
    - `file1; touch file 2`
- Check and see if both files were created.
