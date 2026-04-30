from app.detector import check_scam

def test_scam_detection():
    # Test a clear scam
    assert check_scam("Click here to claim your prize") == "SCAM ⚠️"
    
def test_safe_message():
    # Test a normal message
    assert check_scam("Hey, are we still meeting for lunch?") == "NOT SCAM ✅"
    
def test_empty_message():
    # Test edge case: empty input
    assert check_scam("") == "Please enter a message."