# Password Security Analyzer

A small project that rates how strong a password is. It reports four things: **length**, **entropy**, **score** and **verdict**.

## What's in here

- `password_strength_checker.py` is the command-line version. Run it with `python3 password_strength_checker.py`.
- `password-strength-analyzer.html` is the same scoring as a web page. Open it in a browser. It runs entirely on your machine, nothing is sent or saved, and it has a light and dark theme switch.

## How the score works

- **Length** is the number of characters.
- **Entropy** is length x log2(pool size). The pool adds 26 for lowercase letters, 26 for uppercase letters, 10 for digits and 32 if the password has a symbol from the listed set.
- **Score** adds 10 each for a lowercase letter, an uppercase letter and a digit, 20 for a listed symbol, 3 points per character, and half the entropy rounded down. It stops at 100.
- **Common passwords** such as `123456`, `password` and `admin` always score 0.
- **Verdict**: under 40 is Weak, under 60 Moderate, under 80 Strong, and 80 or more Very Strong.

## Known limits

The common-password list is short and only matches the whole password. The score does not look for patterns such as `1234` or dictionary words. Blocking reuse of old passwords with a database is a possible next step.
