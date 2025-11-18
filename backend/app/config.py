import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

HISTORY_FILE = DATA_DIR / "history.json"

BLACKLIST_URLS = [
    "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt",
    "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-NEW-today.txt",
    "https://raw.githubusercontent.com/AmnestyTech/investigations/master/2021-07-18_nso/domains.txt",
]

KNOWN_BRANDS = [
    "google.com",
    "facebook.com",
    "paypal.com",
    "microsoft.com",
    "apple.com",
    "icloud.com",
    "amazon.com",
    "bankofamerica.com",
    "hsbc.com",
    "itau.com.br",
    "bb.com.br",
]

SUSPICIOUS_KEYWORDS = [
    "verify your account",
    "update your password",
    "suspended account",
    "verify now",
    "click here to verify",
    "ssn",
    "social security number",
    "credit card number",
    "cvv",
    "expires soon",
    "urgent action required",
]

DYNAMIC_DNS_PROVIDERS = [
    "duckdns.org",
    "no-ip.org",
    "no-ip.com",
    "dyndns.org",
    "hopto.org",
    "zapto.org",
    "dynv6.net",
]

