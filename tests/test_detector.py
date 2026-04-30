from app.detector import analyze_message

def test_scam_detection():
    # Test a clear scam with a URL
    result = analyze_message("Click here to claim your prize http://fake.com")
    assert "SCAM" in result['status']
    assert result['risk_score'] >= 60
    assert len(result['findings']) > 0
    
def test_safe_message():
    # Test a normal message
    result = analyze_message("Hey, are we still meeting for lunch?")
    assert "NOT SCAM" in result['status']
    assert result['risk_score'] == 0
    
def test_homoglyph_attack():
    # Test using a Cyrillic 'а' instead of English 'a'
    result = analyze_message("Please login to pаypal")
    assert result['risk_score'] >= 60
    assert any("Homoglyph" in finding for finding in result['findings'])