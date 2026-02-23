"""
ZeroThreat Web Plugin: Default Credentials Detector
Checks common admin paths for default username/password combinations.
Drop any .py file in checks/web/ — it gets auto-loaded.
Each plugin must expose: run(base_url, request_fn, crawl_result) -> list[dict] | dict | None
"""

import urllib.parse, copy

FINDING = {
    "id":"PLG-WEB-001","title":"Default Credentials Accepted",
    "severity":"CRITICAL","cvss_score":9.8,
    "description":"The application accepted a well-known default username/password combination. Attackers use automated scanners with default credential lists.",
    "affected":"Web Application Login",
    "recommendation":"Change all default credentials immediately. Implement account lockout after failed attempts. Add MFA.",
    "cve_ids":[],"cwe_ids":["CWE-1188","CWE-521"],
    "confidence":"HIGH","evidence":"","evidence_detail":{},
    "adjusted_score":9.8,"internet_exposed":False,"auth_required":False,"pii_involved":False,
}

# Safe, widely-known default creds (not weaponized — just credential pairs found in public CVE docs)
DEFAULT_CREDS = [
    ("admin","admin"), ("admin","password"), ("admin","123456"),
    ("admin",""), ("root","root"), ("admin","admin123"),
    ("guest","guest"), ("user","user"),
]

LOGIN_ENDPOINTS = [
    "/admin", "/login", "/wp-login.php", "/admin/login",
    "/user/login", "/auth/login", "/panel",
]

def run(base_url, request_fn, crawl_result):
    results = []
    tested = set()

    # Collect login forms from crawl results
    form_targets = []
    if crawl_result and crawl_result.forms:
        for form in crawl_result.forms:
            action = form.get("action","")
            fields = form.get("fields",[])
            method = form.get("method","POST")
            # Look for login-style forms (has username + password fields)
            has_user = any(f in fields for f in ["username","user","email","login","name"])
            has_pass = any(f in fields for f in ["password","pass","passwd","pwd"])
            if has_user and has_pass:
                form_targets.append((action, method, fields))

    # Also try known login paths
    for path in LOGIN_ENDPOINTS:
        url = base_url + path
        status, body, headers = request_fn(url)
        if status in (200, 401) and any(kw in body.lower() for kw in ["password","login","signin","username"]):
            # Extract form fields
            import re
            fields = re.findall(r'name=["\']([^"\']+)["\']', body, re.IGNORECASE)
            user_f = next((f for f in fields if f.lower() in ["username","user","email","login"]), None)
            pass_f = next((f for f in fields if f.lower() in ["password","pass","passwd","pwd"]), None)
            action_m = re.search(r'action=["\']([^"\']*)["\']', body, re.IGNORECASE)
            action = urllib.parse.urljoin(url, action_m.group(1)) if action_m else url
            if user_f and pass_f:
                form_targets.append((action, "POST", fields))

    if not form_targets:
        return None

    for action, method, fields in form_targets:
        key = action
        if key in tested: continue
        tested.add(key)

        for user, pwd in DEFAULT_CREDS[:4]:  # Limit to 4 attempts per endpoint
            # Build form data with discovered field names
            user_f = next((f for f in fields if f.lower() in ["username","user","email","login"]), "username")
            pass_f = next((f for f in fields if f.lower() in ["password","pass","passwd","pwd"]), "password")
            data = {user_f: user, pass_f: pwd}

            try:
                status, body, headers = request_fn(action, method="POST", data=data)
                # Signs of successful login:
                success_indicators = [
                    status in (301, 302) and "/login" not in headers.get("Location","").lower(),
                    "dashboard" in body.lower(),
                    "logout" in body.lower(),
                    "welcome" in body.lower() and status == 200,
                    "invalid" not in body.lower() and "incorrect" not in body.lower() and status == 200,
                ]
                if any(success_indicators[:3]):  # Only flag on strong indicators
                    v = copy.deepcopy(FINDING)
                    v["evidence"] = f"Default credentials accepted at {action}: {user}:{pwd}"
                    v["evidence_detail"] = {
                        "check_id":"PLG-WEB-001","endpoint":action,"parameter":f"{user_f},{pass_f}",
                        "request_snippet":f"POST {action}\n{user_f}={user}&{pass_f}={pwd}",
                        "response_snippet":f"HTTP {status} | Location: {headers.get('Location','')}",
                        "triggered_by":"Default credential probe","confidence":"HIGH",
                    }
                    results.append(v)
                    break  # Don't keep trying after success
            except: pass

    return results if results else None
