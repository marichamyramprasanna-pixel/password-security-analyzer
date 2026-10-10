import math
import re

# List of common/leaked passwords to check against
COMMON_PASSWORDS = ["123456", "password", "123456789", "12345678", "12345", "admin", "welcome"]

def calculate_entropy(password):
    """Calculates the cryptographic entropy (unpredictability) of the password in bits."""
    pool_size = 0
    if re.search(r"[a-z]", password):
        pool_size += 26
    if re.search(r"[A-Z]", password):
        pool_size += 26
    if re.search(r"[0-9]", password):
        pool_size += 10
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        pool_size += 32

    if pool_size == 0 or not password:
        return 0.0

    # Entropy formula: length * log2(pool_size)
    entropy = len(password) * math.log2(pool_size)
    return entropy

def score_password(password):
    """Evaluates password length, entropy, common leaks, and rule-based scoring."""
    length = len(password)
    entropy = calculate_entropy(password)

    # Rule-based scoring
    score = 0
    if re.search(r"[a-z]", password):
        score += 10
    if re.search(r"[A-Z]", password):
        score += 10
    if re.search(r"[0-9]", password):
        score += 10
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 20

    # Factor in length and entropy to the total score (capped at 100)
    base_score = min(score + (length * 3) + int(entropy * 0.5), 100)

    # Check if found in common/leaked password list
    if password.lower() in COMMON_PASSWORDS:
        base_score = 0
        verdict = "Weak"
    elif base_score < 40:
        verdict = "Weak"
    elif base_score < 60:
        verdict = "Moderate"
    elif base_score < 80:
        verdict = "Strong"
    else:
        verdict = "Very Strong"

    return {
        "length": length,
        "entropy": round(entropy, 2),
        "score": base_score,
        "verdict": verdict
    }

def main():
    print("--- Password Strength Checker ---")
    password = input("Enter a password to check: ")

    result = score_password(password)
    print("\n--- Password Analysis ---")
    print(f"Length: {result['length']}")
    print(f"Entropy: {result['entropy']} bits")
    print(f"Score: {result['score']} / 100")
    print(f"Verdict: {result['verdict']}")

if __name__ == "__main__":
    main()
