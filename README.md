# AntiPhish

AntiPhish is a Python-based tool designed to analyze `.eml` email files and detect characteristics commonly associated with phishing attacks. It uses a scoring system to evaluate risk based on suspicious content, link mismatches, domain patterns, and more.

## Features

- Parses `.eml` files using Python's `email` standard library
- Scans email subject and body for high-risk phishing keywords
- Extracts and analyzes embedded links:
  - Flags when the displayed link text doesn’t match the actual URL
  - Detects URLs with suspicious or uncommon top-level domains (TLDs)
  - Identifies IP address-based URLs
- Assigns a phishing risk score with a breakdown of all detected issues
- Simple GUI file selection using Tkinter

## How It Works

Once an `.eml` file is selected, the program:
1. Extracts the subject, sender, and HTML/plaintext body
2. Searches for common phishing terms (e.g., "urgent", "verify", "suspend")
3. Parses all anchor tags (`<a>`) and checks:
   - If the link text matches the actual URL
   - If the domain is unusual or potentially malicious
   - If the link points to a raw IP address
4. Compiles a score and lists reasons for each flagged item

## Phishing Risk Scoring

- W.I.P.

## Installation

1. Clone the repository
2. pip install beautifulsoup4 tldextract
3. py main.py

## Author

Created by Ryan Medeiros (https://github.com/ryanfmedeiros)
