"""
Round-2 detection rules: USERNAME, WIFI_CODE, ACCESS_CARD, SERIAL_NUMBER, BANK_ACCOUNT, and the
regex fallback used when the Presidio analyzer is unavailable. Runs the real detect_pii().
Run from the project root:  python tests/test_detection_rules_2.py
"""
import os
import sys
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import gateway.pii_detector as pd


def spans(text, entity):
    return [text[r.start:r.end] for r in pd.detect_pii(text) if r.entity_type == entity]


def assert_found(text, entity, expected):
    got = spans(text, entity)
    assert expected in got, f"{entity}: expected {expected!r} in {got!r} for {text!r}"


def assert_absent(text, entity):
    got = spans(text, entity)
    assert not got, f"{entity}: unexpected {got!r} for {text!r}"


# ---------------------------------------------------------------- a. USERNAME
USERNAME_POSITIVE = [
    ("Her username kiran.rao was reset", "kiran.rao"),
    ("user id: dev_77 on the build server", "dev_77"),
    ("login ID is maya2024 today", "maya2024"),
    ("The user name priya_s9 is locked", "priya_s9"),
    ("login name = r.kumar42", "r.kumar42"),
    ("Use userid: ops.lead3 for the portal", "ops.lead3"),
]
USERNAME_NEGATIVE = [
    "Enter the username field",
    "The username and password are required",
    "Bring your user id card",
    "The username is required",
    "Type a username e.g. admin",
    "Choose a username policy",
    "login id missing from the form",
]


def test_username_positive():
    for text, expected in USERNAME_POSITIVE:
        assert_found(text, "USERNAME", expected)


def test_username_exact_span():
    for text, expected in USERNAME_POSITIVE:
        assert spans(text, "USERNAME") == [expected], (text, spans(text, "USERNAME"))


def test_username_negative():
    for text in USERNAME_NEGATIVE:
        assert_absent(text, "USERNAME")


# ---------------------------------------------------------------- b. WIFI_CODE
WIFI_POSITIVE = [
    ("The Wi-Fi code is NX-4471-ZK", "NX-4471-ZK"),
    ("wifi password: Guest@4471", "Guest@4471"),
    ("WiFi key NX4471", "NX4471"),
    ("the guest wi-fi passcode is Cafe#2024 today", "Cafe#2024"),
    ("Wi Fi PIN 482913 works", "482913"),
    ("wifi passphrase: blue-sky-77", "blue-sky-77"),
]
WIFI_NEGATIVE = [
    "Ask the desk for the wifi code",
    "The wifi password policy applies",
    "The Wi-Fi key is on the router",
    "The wifi code is required",
    "wifi password reset needed",
    "Wi-Fi is down in the lobby",
]


def test_wifi_positive():
    for text, expected in WIFI_POSITIVE:
        assert_found(text, "WIFI_CODE", expected)


def test_wifi_negative():
    for text in WIFI_NEGATIVE:
        assert_absent(text, "WIFI_CODE")


# ---------------------------------------------------------------- c. ACCESS_CARD
ACCESS_POSITIVE = [
    ("access card number 884-221-90", "884-221-90"),
    ("access card no: 77120", "77120"),
    ("door card 5521-88", "5521-88"),
    ("entry card number is E-90321 now", "E-90321"),
    ("visitor card #V4471 was issued", "V4471"),
    ("security card id 33-1209 returned", "33-1209"),
]
ACCESS_NEGATIVE = [
    "The access card number is printed on it",
    "Tap the access card at the reader",
    "The door card readers were replaced",
    "Access card holders may enter",
    "A visitor card is required",
    "The access card 12 floors are open",
]


def test_access_card_positive():
    for text, expected in ACCESS_POSITIVE:
        assert_found(text, "ACCESS_CARD", expected)


def test_access_card_negative():
    for text in ACCESS_NEGATIVE:
        assert_absent(text, "ACCESS_CARD")


# ---------------------------------------------------------------- d. SERIAL_NUMBER
SERIAL_POSITIVE = [
    ("serial number 7K2M9Q1", "7K2M9Q1"),
    ("S/N: ABC12345", "ABC12345"),
    ("serial no. 99-ZX-1043", "99-ZX-1043"),
    ("the device serial num XJ-20931 was returned", "XJ-20931"),
    ("serial # LT55X901 on the base", "LT55X901"),
    ("Serial Number: 4491-0022-A", "4491-0022-A"),
]
SERIAL_NEGATIVE = [
    "The serial number is printed underneath",
    "Enter the serial number here",
    "serial no. 12",
    "serial number 1234",
    "Connect the serial port COM3",
    "A serial killer documentary",
    "The s/n ratio is high",
]


def test_serial_positive():
    for text, expected in SERIAL_POSITIVE:
        assert_found(text, "SERIAL_NUMBER", expected)


def test_serial_negative():
    for text in SERIAL_NEGATIVE:
        assert_absent(text, "SERIAL_NUMBER")


# ---------------------------------------------------------------- e. BANK_ACCOUNT
BANK_POSITIVE = [
    ("bank account number 123456789012", "123456789012"),
    ("account no: 50100234567890", "50100234567890"),
    ("Transfer to a/c 9876543210123 today", "9876543210123"),
    ("acct no. 0012345678", "0012345678"),
    ("pay a/c no 1234-5678-9012 please", "1234-5678-9012"),
    ("my bank account is 112233445566778", "112233445566778"),
]
BANK_NEGATIVE = [
    "account number 12345",
    "account balance is 123456789012",
    "Aadhaar 368942105678",
    "My Aadhaar is 3689 4210 5678",
    "Open an account today 123456789012",
    "account 12345678",
    "account no 1234567890123456789",
]


def test_bank_account_positive():
    for text, expected in BANK_POSITIVE:
        assert_found(text, "BANK_ACCOUNT", expected)


def test_bank_account_beats_aadhaar_on_its_span():
    for text, expected in BANK_POSITIVE:
        assert expected not in spans(text, "AADHAAR_NUMBER"), (text, spans(text, "AADHAAR_NUMBER"))


def test_bank_account_negative():
    for text in BANK_NEGATIVE:
        assert_absent(text, "BANK_ACCOUNT")


def test_aadhaar_after_aadhaar_cue_stays_aadhaar():
    assert_found("Aadhaar number 368942105678", "AADHAAR_NUMBER", "368942105678")
    assert_found("My Aadhaar is 3689 4210 5678", "AADHAAR_NUMBER", "3689 4210 5678")
    assert_found("aadhaar: 5123 4567 8901 on file", "AADHAAR_NUMBER", "5123 4567 8901")


def test_bank_account_is_pseudonymized_like_other_entities():
    text = "bank account number 123456789012"
    sanitized, mapping, has_pii = pd.anonymize_prompt(text)
    assert has_pii and "123456789012" not in sanitized, sanitized
    assert "[TOKEN_HMAC_BANK_" in sanitized, sanitized
    assert pd.deanonymize_response(sanitized, mapping).startswith("bank account number 123456789012")


# ---------------------------------------------------------------- f. FALLBACK BRANCH
FALLBACK_CASES = [
    ("PHONE_NUMBER", "Call me on +91 98765 43210 now", "+91 98765 43210"),
    ("PHONE_NUMBER", "Dial 98765-43210 please", "98765-43210"),
    ("EMPLOYEE_ID", "my employee id is EMP-20457", "EMP-20457"),
    ("PASSWORD", "login password Welcome@2024 expires", "Welcome@2024"),
    ("PASSWORD", "password is Secret@123", "Secret@123"),
    ("MONEY", "balance is 45000 INR", "45000 INR"),
    ("USERNAME", "username anil.verma was used", "anil.verma"),
    ("WIFI_CODE", "Wi-Fi code is NX-4471-ZK", "NX-4471-ZK"),
    ("ACCESS_CARD", "access card number 884-221-90", "884-221-90"),
    ("SERIAL_NUMBER", "serial number 7K2M9Q1", "7K2M9Q1"),
    ("BANK_ACCOUNT", "bank account number 123456789012", "123456789012"),
    ("AADHAAR_NUMBER", "Aadhaar 3689 4210 5678", "3689 4210 5678"),
]


def _fallback_spans(text, entity):
    res = pd.filter_overlapping_results(pd._fallback_detect(text))
    return [text[r.start:r.end] for r in res if r.entity_type == entity]


def test_fallback_function_directly():
    for entity, text, expected in FALLBACK_CASES:
        got = _fallback_spans(text, entity)
        assert expected in got, f"fallback {entity}: expected {expected!r} in {got!r} for {text!r}"


def test_fallback_negatives():
    for entity, text in [("PHONE_NUMBER", "Reference 1234567890 was issued"),
                         ("PHONE_NUMBER", "Aadhaar 3689 4210 5678"),
                         ("PASSWORD", "Read the password policy first"),
                         ("EMPLOYEE_ID", "Bring your employee id card"),
                         ("MONEY", "I walked 5000 steps"),
                         ("USERNAME", "The username field"),
                         ("SERIAL_NUMBER", "serial number 1234"),
                         ("BANK_ACCOUNT", "Aadhaar 368942105678")]:
        assert not _fallback_spans(text, entity), (entity, text, _fallback_spans(text, entity))


def test_detect_pii_uses_fallback_when_analyzer_missing():
    saved = pd.analyzer
    pd.analyzer = None
    try:
        for entity, text, expected in FALLBACK_CASES:
            got = spans(text, entity)
            assert expected in got, f"detect_pii(no analyzer) {entity}: expected {expected!r} in {got!r}"
    finally:
        pd.analyzer = saved


def test_both_paths_agree_on_custom_entities():
    custom = {"PHONE_NUMBER", "EMPLOYEE_ID", "PASSWORD", "MONEY", "USERNAME", "WIFI_CODE",
              "ACCESS_CARD", "SERIAL_NUMBER", "BANK_ACCOUNT", "AADHAAR_NUMBER"}
    texts = [t for _, t, _ in FALLBACK_CASES] + [
        "Please contact me on +91 98765 43210 or at a@b.com.",
        "wifi password: Guest@4471 and door card 5521-88",
        "S/N: ABC12345 for a/c 9876543210123",
    ]
    for text in texts:
        normal = sorted((r.entity_type, text[r.start:r.end]) for r in pd.detect_pii(text) if r.entity_type in custom)
        saved, pd.analyzer = pd.analyzer, None
        try:
            fallback = sorted((r.entity_type, text[r.start:r.end]) for r in pd.detect_pii(text) if r.entity_type in custom)
        finally:
            pd.analyzer = saved
        assert normal == fallback, f"{text!r}: normal={normal} fallback={fallback}"


if __name__ == "__main__":
    failed = 0
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print("PASS", name)
            except Exception as e:
                failed += 1
                print("FAIL", name, "-", f"{type(e).__name__}: {e}")
    sys.exit(1 if failed else 0)
