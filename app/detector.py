import re
import tldextract
from thefuzz import fuzz

# Categorized threat intelligence
SCAM_KEYWORDS = {
    "financial": ["lottery", "won", "prize", "free money", "bank", "account suspended"],
    "urgency": ["urgent", "immediately", "claim now", "expires", "action required"],
    "action": ["click here", "password", "otp", "login", "verify", "update details"]
}

SUSPICIOUS_CHARS = set("аеорсху") 

# Trusted domains (Whitelist)
TRUSTED_DOMAINS = ["google.com", "paypal.com", "github.com", "microsoft.com", "apple.com"]

def analyze_message(message):
    if not message:
        return {"status": "ERROR", "reason": "Please enter a message.", "risk_score": 0}
        
    message_lower = message.lower()
    findings = []
    risk_score = 0

    # 1. Advanced URL Extraction & Domain Analysis (tldextract)
    urls = re.findall(r'(https?://\S+)', message_lower)
    for url in urls:
        extracted = tldextract.extract(url)
        root_domain = f"{extracted.domain}.{extracted.suffix}"
        
        # Check for Subdomain spoofing (e.g., paypal.scam-site.com)
        if extracted.subdomain:
            findings.append(f"Suspicious URL structure detected: Subdomains used in {root_domain}")
            risk_score += 20
            
        if root_domain not in TRUSTED_DOMAINS:
            findings.append(f"Untrusted root domain detected: '{root_domain}'. Do not click.")
            risk_score += 40
        else:
            findings.append(f"Verified trusted domain: '{root_domain}' ✅")

    # 2. Fuzzy Keyword Matching (thefuzz)
    # This catches "l0ttery", "p4ssword", "b@nk"
    words_in_message = message_lower.split()
    for category, keywords in SCAM_KEYWORDS.items():
        for keyword in keywords:
            for word in words_in_message:
                # Calculate similarity (above 85% similarity triggers the flag)
                if fuzz.ratio(keyword, word) > 85:
                    findings.append(f"Detected {category} trigger (Fuzzy Match): '{word}' looks like '{keyword}'")
                    risk_score += 25

    # 3. Homoglyph Attack Detection
    homoglyphs = [char for char in message_lower if char in SUSPICIOUS_CHARS]
    if homoglyphs:
        findings.append("CRITICAL: Detected hidden foreign characters (Homoglyph attack).")
        risk_score += 60

    # 4. Final Threat Calculation
    if risk_score >= 60:
        status = "SCAM ⚠️"
    elif risk_score > 0:
        status = "SUSPICIOUS 🧐"
    else:
        status = "NOT SCAM ✅"

    return {
        "status": status,
        "risk_score": min(risk_score, 100), 
        "findings": findings
    }