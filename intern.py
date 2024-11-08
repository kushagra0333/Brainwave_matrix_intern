import re 
phishing_keywords = ["login", "verify", "account", "update", "secure", "bank", "password", "signin", "confirm","0"]

def contains_phishing_keywords(url):
    for keyword in phishing_keywords:
        if keyword in url.lower():
            return True
    return False


def contains_suspicious_patterns(url):  
    ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
    if ip_pattern.search(url):
        return True
    subdomain_pattern = re.compile(r'(\w+\.){3,}')
    if subdomain_pattern.search(url):
        return True

    return False

def scan_for_phishing(urls):
    for url in urls:
        if contains_phishing_keywords(url):
            print(f"Potential phishing URL detected: {url}")
        elif contains_suspicious_patterns(url):
            print(f"Suspicious URL detected: {url}")
        else:
            print(f"URL seems safe: {url}")

urls_to_scan = [
    "http://example.com",
    "http://login-bank.com",
    "http://192.168.1.1",
    "http://secure-login.example.com",
    "http://update-password.com",
    "http://go0gle.com"
]

scan_for_phishing(urls_to_scan)