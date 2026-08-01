import re

def analyze_password(password):

    score = 0

    if len(password) >= 8:
        score += 1

    if re.search("[A-Z]", password):
        score += 1

    if re.search("[0-9]", password):
        score += 1

    if re.search("[!@#$%^&*]", password):
        score += 1

    if score <= 1:
        return "Weak"

    elif score == 2:
        return "Medium"

    else:
        return "Strong"