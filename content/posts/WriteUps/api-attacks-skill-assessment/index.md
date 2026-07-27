+++
title = 'API Attack Skill Assessment'
date = '2026-07-05T08:36:42-04:00'
draft = false
slug = 'api-attacks-skill-assessment'
description = 'Escalating from customer to supplier via role enumeration, security-question brute-force, and JWT re-authentication to achieve RCE.'
tags = ["Web", "HTB"]
difficulty = 'hard'
+++
We have a web application that should be secured than `v0` and `v1`, and the question said that `Submit the contents of the flag at '/flag.txt'.`
After seeing that the flag is in `/flag.txt`, I thought about searching for SSRF to LFI. This enable me to know the local files paths and get the flag.
- First I signed in using the credentials provided `htbpentester@hackthebox.com:HTBPentester` as a customer.
- Then I want to check the roles to see what I actions I can do using these roles, so navigating to `/api/v2/roles/current-user`:
```json
{
  "roles": [
    "Suppliers_Get",
    "Suppliers_GetAll"
  ]
}
```
- I went to `supplier` section to check what actions I can do and data I can get.
- Sending a request to `/api/v2/suppliers` we will get some PII:
<img width="893" height="503" alt="Screenshot 2026-06-26 020014" src="https://github.com/user-attachments/assets/2f017294-cc20-44a7-b137-3ae4492d9445" />
- Some emails and security questions and such, save it and continue. 
- Still searching for endpoint enable me to upload a file to know the path of the files, I found `/api/v2/suppliers/current-user/cv` endpoint and tried to upload a `shell.php` file but give me unauthorized.
- I really tried all endpoints that accept files to test but all of them give me unauthorized and need suppliers' roles, so I got back to the data I have to find how can I use them, can I get a supplier email from them ??!
- The data provide email and security question, if you scrolled the file you find that some of them has a security question so I used AI to filter me the emails that have a security question `What is your favorite color?` and this give me some emails.
- If you noticed the authentication section you will find an endpoint that resets passwords using security questions --> `/api/v2/authentication/suppliers/passwords/resets/security-question-answers` and requires three parameters:
```json
{
  "SupplierEmail": "string",
  "SecurityQuestionAnswer": "string",
  "NewPassword": "string"
}
```
- That's greatttt. let's brute forcing this.
- Using the filtered emails and created wordlist with the all possible colors I used burp intruder with `cluster bomb atatack` which try all emails with all colors and typed `true` in `Grep Match` option to match the correct true credentials.
<img width="893" height="503" alt="Screenshot 2026-06-26 020014" src="https://github.com/user-attachments/assets/9378164c-0546-4eca-9d64-6fd0866baa49" />
- We get a valid one, the next step is to sign in --> new JWT --> Authenticate.
- After doing this, I checked the available roles for this user:
```json
{
  "errorMessage": "User does not have any roles assigned"
}
```
That's Interesting!!!
- What ever, let's check the endpoints which accept uploading files again, and I find this one in supplier too --> `POST /api/v2/suppliers/current-user/cv` and requires no roles too:
<img width="893" height="503" alt="Screenshot 2026-06-26 020014" src="https://github.com/user-attachments/assets/bd311275-3b45-43c4-add7-b1b54e7672b9" />
- I uploaded a random pdf file and done it's successfully uploaded:
<img width="893" height="503" alt="Screenshot 2026-06-26 020014" src="https://github.com/user-attachments/assets/4978f3cb-af93-473e-a9d6-098c0c1fbcf4" />
- If we sent a request to `GET /api/v2/suppliers/current-user` we will find our file is saved.
<img width="893" height="503" alt="Screenshot 2026-06-26 020014" src="https://github.com/user-attachments/assets/6e3fd0ff-a110-4182-bb17-069acb42eecf" />
- Now I want to update the file path to point to our flag, so I made a request to `PATCH /api/v2/suppliers/current-user/cv` and typed `../../../../flag.txt`. 
**NOTE:** I used path traversal because I don't know the exact path of the flag so we want to make sure that the flag will save in our cv data successfully.
- These parameters are required to update the file:
```json
{
  "SecurityQuestion": "string",
  "SecurityQuestionAnswer": "string",
  "ProfessionalCVPDFFileURI":
  file:///app/wwwroot/SupplierCVs/../../../flag.txt,
  "PhoneNumber": "string",
  "Password": "string"
}
```
The others we can answer some with any random data, and done it's updated.
<img width="891" height="497" alt="image" src="https://github.com/user-attachments/assets/8c601ad8-ac57-4c08-abcf-64094377ed3e" />
- Our Flag is finally here, we just want to view it.
- Sending a request to `GET /api/v2/suppliers/current-user/cv` we will get out flag base64 encoded:
<img width="885" height="528" alt="image" src="https://github.com/user-attachments/assets/73bd032f-b119-4d8d-a974-a0252867c732" />
JUST DECODE IT AND DONNEEEEE ;)
