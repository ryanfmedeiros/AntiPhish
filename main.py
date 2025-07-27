import tkinter as tk
from tkinter import filedialog
import email
from email import policy
from email.parser import BytesParser
import re
from bs4 import BeautifulSoup
import tldextract

PHISHING_KEYWORDS = [
    "urgent", "verify your account", "password", "click here",
    "suspend", "refund", "action required", "login", "unusual activity"
]

SUSPICIOUS_TLDS = ["ru", "xyz", "top", "tk", "ml", "cf"]
URL_SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"]

root = tk.Tk()
root.withdraw()
file_path = filedialog.askopenfilename(
    title="Select an EML file",
    filetypes=[("Email files", "*.eml")]
)

def load_email(file):
    with open(file, 'rb') as f:
        return BytesParser(policy=policy.default).parse(f)

def extract_links(html_content):
    soup = BeautifulSoup(html_content, 'html.parser')
    links = []
    for a in soup.find_all('a', href=True):
        text = a.get_text(strip=True)
        href = a['href']
        links.append((text, href))
    return links

def is_ip_address(url):
    return re.match(r'^https?://\d{1,3}(\.\d{1,3}){3}', url) is not None

def extract_domain(url):
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}"

def contains_suspicious_patterns(url):
    reasons = []
    score = 0

    # Shortener detection
    domain = extract_domain(url)
    if domain in URL_SHORTENERS:
        score += 2
        reasons.append(f"URL uses a known shortener: {domain}")

    # Obfuscated patterns
    if '%' in url or '@' in url:
        score += 2
        reasons.append(f"URL contains obfuscation characters (% or @): {url}")

    # Long query parameters
    if re.search(r'[\?&](token|auth|sessionid)=\w{20,}', url):
        score += 2
        reasons.append(f"URL contains long authentication token: {url}")

    return score, reasons

def analyze_email(msg):
    score = 0
    reasons = []

    subject = msg['subject'] or ''
    from_header = msg['from'] or ''
    body = ""

    html_part = msg.get_body(preferencelist=('html'))
    if html_part:
        body = html_part.get_content()
    else:
        plain = msg.get_body(preferencelist=('plain'))
        body = plain.get_content() if plain else ""

    # Keyword check
    for kw in PHISHING_KEYWORDS:
        if kw in subject.lower() or kw in body.lower():
            score += 1
            reasons.append(f"Keyword found: {kw}")

    # Link checks
    if html_part:
        links = extract_links(body)
        for text, href in links:
            text_domain = extract_domain(text) if "." in text else None
            href_domain = extract_domain(href)

            # Mismatched domains (excluding generic text)
            if text_domain and text_domain != href_domain:
                score += 3
                reasons.append(f"Link text domain '{text_domain}' doesn't match actual link domain '{href_domain}'")

            # Suspicious TLD
            if href_domain.split('.')[-1] in SUSPICIOUS_TLDS:
                score += 2
                reasons.append(f"Suspicious TLD: .{href_domain.split('.')[-1]}")

            # IP address in URL
            if is_ip_address(href):
                score += 3
                reasons.append(f"URL points to an IP address: {href}")

            # Suspicious URL patterns
            url_score, url_reasons = contains_suspicious_patterns(href)
            score += url_score
            reasons.extend(url_reasons)

    return score, reasons

if __name__ == "__main__":
    if file_path:
        print(f"Selected file uploaded: {file_path}")
        msg = load_email(file_path)
        score, reasons = analyze_email(msg)
        print(f"Phishing Risk Score: {score}")
        print("Flags Detected:")
        for r in reasons:
            print(f"- {r}")
            print("\n")
    else:
        print("No file selected.")
