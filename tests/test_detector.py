from app.detector import analyze_message

def test_fuzzy_matching():
    # Test catching a hacker typo "p4ssw0rd"
    result = analyze_message("Please update your p4ssword immediately")
    assert result['risk_score'] >= 25
    assert any("Fuzzy Match" in finding for finding in result['findings'])

def test_domain_spoofing():
    # Test catching a fake subdomain trick
    result = analyze_message("Login here: http://paypal.secure-login-update.com")
    assert "SCAM" in result['status']
    assert any("Untrusted root domain" in finding for finding in result['findings'])
    
def test_safe_message():
    result = analyze_message("Hey, are we still meeting for lunch?")
    assert "NOT SCAM" in result['status']
    assert result['risk_score'] == 0