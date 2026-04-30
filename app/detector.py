SCAM_KEYWORDS = [
    "lottery", "won", "prize", "click here",
    "urgent", "bank", "password", "otp",
    "free money", "claim now", "account suspended"
]

def check_scam(message):
    if not message:
        return "Please enter a message."
        
    message_lower = message.lower()
    for word in SCAM_KEYWORDS:
        if word in message_lower:
            return "SCAM ⚠️"
    return "NOT SCAM ✅"