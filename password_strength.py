#!/usr/bin/env python3
"""
Password Strength Checker
-------------------------
Scores a password on length, character variety, and common weaknesses,
then classifies it and gives actionable feedback.

Usage:
    python password_strength.py              # interactive (hidden input)
    python password_strength.py "MyP@ss123"  # check a single password
"""

import getpass
import re
import string
import sys

COMMON_PASSWORDS = {
    "password", "123456", "12345678", "123456789", "qwerty", "abc123",
    "letmein", "welcome", "admin", "iloveyou", "monkey", "dragon",
    "football", "login", "passw0rd", "master", "111111", "000000",
}

KEYBOARD_SEQUENCES = ["qwerty", "asdfgh", "zxcvbn", "123456", "abcdef", "098765"]


def analyze(password: str) -> dict:
    """Return a dict of checks and a numeric score (0-100) for the password."""
    length = len(password)
    checks = {
        "lowercase": bool(re.search(r"[a-z]", password)),
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "digit": bool(re.search(r"\d", password)),
        "special": any(c in string.punctuation for c in password),
    }

    score = 0
    feedback = []

    # --- Length (up to 40 points) ---
    if length >= 16:
        score += 40
    elif length >= 12:
        score += 30
    elif length >= 8:
        score += 18
    else:
        score += max(length, 0) * 2
        feedback.append(f"Too short ({length} characters). Use at least 12.")
    if 8 <= length < 12:
        feedback.append("Length is acceptable, but 12+ characters is much safer.")

    # --- Character variety (15 points each, max 60 -> scaled below) ---
    variety_points = {"lowercase": 10, "uppercase": 15, "digit": 15, "special": 20}
    messages = {
        "lowercase": "Add lowercase letters (a-z).",
        "uppercase": "Add uppercase letters (A-Z).",
        "digit": "Add numbers (0-9).",
        "special": "Add special characters (e.g. ! @ # $ % ^ & *).",
    }
    for name, present in checks.items():
        if present:
            score += variety_points[name]
        else:
            feedback.append(messages[name])

    # --- Penalties ---
    lowered = password.lower()

    if lowered in COMMON_PASSWORDS:
        score = min(score, 10)
        feedback.append("This is a very common password. Attackers try it first.")
    elif any(common in lowered for common in COMMON_PASSWORDS if len(common) >= 6):
        score -= 15
        feedback.append("Contains a common password or word. Avoid predictable words.")

    if re.search(r"(.)\1{2,}", password):
        score -= 10
        feedback.append("Avoid repeating the same character 3+ times (e.g. 'aaa').")

    if any(seq in lowered for seq in KEYBOARD_SEQUENCES):
        score -= 10
        feedback.append("Avoid keyboard/sequential patterns like 'qwerty' or '123456'.")

    if length and password.isalpha():
        feedback.append("Letters only is easy to crack. Mix in numbers and symbols.")
    elif length and password.isdigit():
        score -= 10
        feedback.append("Numbers only is extremely weak. Mix in letters and symbols.")

    # Unique character ratio: rewards non-repetitive passwords
    if length and len(set(password)) / length < 0.5:
        score -= 5
        feedback.append("Too many repeated characters. Use a more varied mix.")

    score = max(0, min(100, score))
    return {"length": length, "checks": checks, "score": score, "feedback": feedback}


def classify(score: int) -> str:
    if score < 30:
        return "Very Weak"
    if score < 50:
        return "Weak"
    if score < 70:
        return "Moderate"
    if score < 90:
        return "Strong"
    return "Very Strong"


def estimate_charset(password: str) -> int:
    size = 0
    if re.search(r"[a-z]", password):
        size += 26
    if re.search(r"[A-Z]", password):
        size += 26
    if re.search(r"\d", password):
        size += 10
    if any(c in string.punctuation for c in password):
        size += len(string.punctuation)
    return size


def report(password: str) -> None:
    if not password:
        print("No password entered.")
        return

    result = analyze(password)
    rating = classify(result["score"])
    bar_len = 20
    filled = round(result["score"] / 100 * bar_len)
    bar = "#" * filled + "-" * (bar_len - filled)

    print("\n" + "=" * 44)
    print(" PASSWORD STRENGTH REPORT")
    print("=" * 44)
    print(f" Length      : {result['length']} characters")
    for name, ok in result["checks"].items():
        print(f" {name.capitalize():<11} : {'Yes' if ok else 'No'}")
    print(f" Score       : {result['score']}/100  [{bar}]")
    print(f" Rating      : {rating}")

    charset = estimate_charset(password)
    if charset:
        bits = result["length"] * (charset).bit_length()
        print(f" Est. entropy: ~{bits} bits (upper bound; patterns reduce this)")

    print("-" * 44)
    if result["feedback"]:
        print(" How to improve:")
        for tip in result["feedback"]:
            print(f"  - {tip}")
    else:
        print(" Great job! No improvements needed.")
        print(" Tip: use a unique password for every account.")
    print("=" * 44 + "\n")


def main() -> None:
    if len(sys.argv) > 1:
        report(sys.argv[1])
        return

    print("Password Strength Checker (type 'q' to quit; input is hidden)")
    while True:
        try:
            pwd = getpass.getpass("\nEnter a password: ")
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye!")
            break
        if pwd.lower() == "q":
            print("Goodbye!")
            break
        report(pwd)


if __name__ == "__main__":
    main()
