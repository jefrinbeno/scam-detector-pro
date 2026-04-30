import re

# Categorized threat intelligence
SCAM_KEYWORDS = {
    "financial": ["lottery", "won", "prize", "free money", "bank", "account suspended"],
    "urgency": ["urgent", "immediately", "claim now", "expires", "action required"],
    "action": ["click here", "password", "otp", "login", "verify", "update details"]
}

# Cyrillic characters commonly used in homoglyph (look-alike) attacks
SUSPICIOUS_CHARS = set("аеорсху") 

def analyze_message(message):
    if not message:
        return {"status": "ERROR", "reason": "Please enter a message.", "risk_score": 0}
        
    message_lower = message.lower()
    findings = []
    risk_score = 0

    # 1. URL Extraction (Regex)
    urls = re.findall(r'(https?://\S+)', message_lower)
    if urls:
        findings.append(f"Found {len(urls)} suspicious link(s). Never click unknown links.")
        risk_score += 40

    # 2. Advanced Keyword Analysis
    for category, words in SCAM_KEYWORDS.items():
        for word in words:
            if word in message_lower:
                findings.append(f"Detected {category} trigger word: '{word}'")
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
        "risk_score": min(risk_score, 100), # Cap the score at 100%
        "findings": findings
    }