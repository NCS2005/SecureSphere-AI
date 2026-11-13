"""
Tests for the detection-rule fixes: PHONE, MONEY (currency after number), PASSWORD (no "is"/":"),
EMPLOYEE_ID (cue based). They run the real detect_pii() pipeline (Presidio + spaCy + custom
recognizers + overlap resolution), so a rule only passes if it also wins overlap resolution.
Run from the project root:  python tests/test_detection_rules.py
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import gateway.pii_detector as pd


def spans(text, entity):
    """Text of every surviving span of `entity` after overlap resolution."""
    return [text[r.start:r.end] for r in pd.detect_pii(text) if r.entity_type == entity]


def assert_found(text, entity, expected):
    got = spans(text, entity)
    assert expected in got, f"{entity}: expected {expected!r} in {got!r} for {text!r}"


def assert_absent(text, entity):
    got = spans(text, entity)
    assert not got, f"{entity}: unexpected {got!r} for {text!r}"


# ---------------------------------------------------------------- a. PHONE
PHONE_POSITIVE = [
    ("Call me on 98765-43210 tomorrow", "98765-43210"),
    ("WhatsApp: +91-9123456789 anytime", "+91-9123456789"),
    ("My mobile is 09812345678.", "09812345678"),
    ("Dial 91 8123456780 for support", "91 8123456780"),
    ("Office line +44 20 7946 0958 works", "+44 20 7946 0958"),
    ("US contact: +1 415 555 2671.", "+1 415 555 2671"),
    ("Reach her at 7012345678 after lunch", "7012345678"),
    ("Gulf office +971 50 123 4567 is open", "+971 50 123 4567"),
]

PHONE_NEGATIVE = [
    "Aadhaar 3689 4210 5678 is on file",
    "Aadhaar number 368942105678 was verified",
    "His Aadhaar is 9198 7654 3210",
    "PAN ABCDE1234F belongs to the applicant",
    "Born on 12/03/1990 and joined on 2026-10-31",
    "Pincode 500032 covers the area",
    "Reference 1234567890 was issued",
    "Ticket 5123456789 is closed",
    "The patch scored +25 points over 3 rounds",
]


def test_phone_positive():
    for text, expected in PHONE_POSITIVE:
        assert_found(text, "PHONE_NUMBER", expected)


def test_phone_negative():
    for text in PHONE_NEGATIVE:
        assert_absent(text, "PHONE_NUMBER")


def test_phone_example_includes_prefix():
    assert_found("Please contact me on +91 98765 43210 or at a@b.com.", "PHONE_NUMBER", "+91 98765 43210")


# ---------------------------------------------------------------- b. MONEY
MONEY_POSITIVE = [
    ("He deposited 45000 INR yesterday", "45000 INR"),
    ("The fee is 85000 rupees per term", "85000 rupees"),
    ("I was paid 120000 Rs last month", "120000 Rs"),
    ("Balance of 5000 USD remains", "5000 USD"),
    ("Refund of 7500.50 EUR was issued", "7500.50 EUR"),
    # comma-formatted / prefix forms must keep working
    ("My salary was Rs 85,000 per month", "Rs 85,000"),
    ("Paid 1,25,000 rupees in total", "1,25,000 rupees"),
    ("The price is $1,250,000", "$1,250,000"),
]

MONEY_NEGATIVE = [
    "I walked 5000 steps today",
    "Order 45000 was shipped",
    "INR is the currency code",
    "The inrush of 3 users was fine",
    "5000 users signed up",
    "Chapter 12 rupeesign is missing",
    "Meeting room 4500 is on level two",
]


def test_money_positive():
    for text, expected in MONEY_POSITIVE:
        assert_found(text, "MONEY", expected)


def test_money_negative():
    for text in MONEY_NEGATIVE:
        assert_absent(text, "MONEY")


def test_money_after_number_goes_through_ckks():
    if pd.ckks_engine is None:
        return  # affine fallback active; nothing CKKS-specific to check
    sanitized, mapping, has_pii = pd.anonymize_prompt("My balance is 45000 INR and the fee is 85000 rupees.")
    assert has_pii
    assert "45000" not in sanitized and "85000" not in sanitized, sanitized
    assert len(re.findall(r"\[CKKS_NUM_[0-9a-f]{8}_\d+\]", sanitized)) == 2, sanitized
    assert "45000" not in str(mapping) and "85000" not in str(mapping)


# ---------------------------------------------------------------- c. PASSWORD
PASSWORD_POSITIVE = [
    ("The password Welcome@2024 was shared", "Welcome@2024"),
    ("Her login password Summer$2025 expires soon", "Summer$2025"),
    ("wifi pwd N0rthStar! is on the router", "N0rthStar!"),
    ("my passwd Zx9!kLm2q works", "Zx9!kLm2q"),
    ("admin pwd Abc#1234", "Abc#1234"),
    # existing forms must keep working
    ("password is Secret@123 for now", "Secret@123"),
    ("pwd: Abc#1234", "Abc#1234"),
    ("password = 'Hunter2024'", "Hunter2024"),
]

PASSWORD_NEGATIVE = [
    "Read the password policy first",
    "Use the password reset page",
    "A password manager is recommended",
    "Fill in the password field",
    "I forgot password link was broken",
    "The password protected file is large",
    "A password-based login is weaker",
    "Password rotation every quarter is required",
]


def test_password_positive():
    for text, expected in PASSWORD_POSITIVE:
        assert_found(text, "PASSWORD", expected)


def test_password_negative():
    for text in PASSWORD_NEGATIVE:
        assert_absent(text, "PASSWORD")


# ---------------------------------------------------------------- d. EMPLOYEE_ID
EMPLOYEE_POSITIVE = [
    ("Anil (Employee ID EMP-20457) resigned", "EMP-20457"),
    ("emp id: 20457 for payroll", "20457"),
    ("staff id (A-1043) was used", "A-1043"),
    ("The badge number is B7781 today", "B7781"),
    ("employee number 55021 applies", "55021"),
    ("Employee ID is HR/2291.", "HR/2291"),
    ("her Staff ID: S_88123, please check", "S_88123"),
]

EMPLOYEE_NEGATIVE = [
    "Please bring your employee id card",
    "Show your employee id at the gate",
    "The employee id is required for login",
    "The badge number is printed on the back",
    "Wear your staff id badge",
    "The employee number field is mandatory",
    "Ask HR about the emp id format",
]


def test_employee_id_positive():
    for text, expected in EMPLOYEE_POSITIVE:
        assert_found(text, "EMPLOYEE_ID", expected)


def test_employee_id_span_excludes_cue():
    for text, expected in EMPLOYEE_POSITIVE:
        assert spans(text, "EMPLOYEE_ID") == [expected], (text, spans(text, "EMPLOYEE_ID"))


def test_employee_id_negative():
    for text in EMPLOYEE_NEGATIVE:
        assert_absent(text, "EMPLOYEE_ID")


if __name__ == "__main__":
    failed = 0
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print("PASS", name)
            except AssertionError as e:
                failed += 1
                print("FAIL", name, "-", e)
    sys.exit(1 if failed else 0)
