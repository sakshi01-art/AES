"""
Password Management and Cryptographic Entropy Analysis Subsystem.
Complies with NIST SP 800-63B guidelines and utilizes CSPRNG (secrets).
"""
import math
import secrets
import string
from typing import Dict, List, Any


class PasswordManager:
    """
    Provides password strength assessment, Shannon entropy calculation,
    and CSPRNG-backed password generation.
    """

    @staticmethod
    def calculate_entropy(password: str) -> float:
        """
        Calculates the information entropy of a password in bits.
        Combines character pool diversity with password length: E = L * log2(R)
        """
        if not password:
            return 0.0

        pool_size = 0
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(c in string.punctuation for c in password)

        if has_lower:
            pool_size += 26
        if has_upper:
            pool_size += 26
        if has_digit:
            pool_size += 10
        if has_symbol:
            pool_size += len(string.punctuation)

        if pool_size == 0:
            pool_size = 128

        # Base pool entropy
        pool_entropy = len(password) * math.log2(pool_size)

        # Shannon Entropy for character distribution diversity
        freq: Dict[str, int] = {}
        for char in password:
            freq[char] = freq.get(char, 0) + 1

        shannon_entropy = 0.0
        for count in freq.values():
            p = count / len(password)
            shannon_entropy -= p * math.log2(p)

        # Weighted combination ensuring repeat characters don't inflate entropy
        effective_entropy = min(pool_entropy, (shannon_entropy / math.log2(len(password) or 1) + 0.1) * pool_entropy) if len(password) > 1 else pool_entropy
        return round(min(pool_entropy, effective_entropy), 2)

    @classmethod
    def evaluate_strength(cls, password: str) -> Dict[str, Any]:
        """
        Evaluates password strength and returns rating, score (0-100), color, and feedback.
        """
        if not password:
            return {
                "score": 0,
                "label": "Empty",
                "color": "#6B7280",
                "entropy": 0.0,
                "feedback": ["Please enter a password."]
            }

        length = len(password)
        entropy = cls.calculate_entropy(password)
        feedback: List[str] = []

        score = 0
        if length >= 8:
            score += 20
        else:
            feedback.append("Increase length to at least 8 characters.")

        if length >= 12:
            score += 20
        if length >= 16:
            score += 10

        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(c in string.punctuation for c in password)

        variety = sum([has_lower, has_upper, has_digit, has_symbol])
        score += variety * 12

        if not has_upper:
            feedback.append("Add uppercase letters (A-Z).")
        if not has_digit:
            feedback.append("Add numeric digits (0-9).")
        if not has_symbol:
            feedback.append("Add special symbols (!@#$%^&*).")

        score = max(5, min(100, score))

        if score < 35 or length < 6:
            label = "Very Weak"
            color = "#EF4444"  # Red
        elif score < 60 or length < 8:
            label = "Weak"
            color = "#F59E0B"  # Orange
        elif score < 80:
            label = "Moderate"
            color = "#EAB308"  # Yellow
        elif score < 95:
            label = "Strong"
            color = "#10B981"  # Emerald Green
        else:
            label = "Very Strong"
            color = "#06B6D4"  # Cyan / Shield Blue

        if not feedback:
            feedback.append("Excellent cryptographic password entropy!")

        return {
            "score": score,
            "label": label,
            "color": color,
            "entropy": entropy,
            "feedback": feedback
        }

    @staticmethod
    def generate_password(
        length: int = 18,
        include_upper: bool = True,
        include_lower: bool = True,
        include_digits: bool = True,
        include_symbols: bool = True
    ) -> str:
        """
        Generates a cryptographically secure random password using CSPRNG (secrets module).
        Guarantees at least one character from each enabled charset.
        """
        charset = ""
        mandatory_chars = []

        if include_lower:
            charset += string.ascii_lowercase
            mandatory_chars.append(secrets.choice(string.ascii_lowercase))
        if include_upper:
            charset += string.ascii_uppercase
            mandatory_chars.append(secrets.choice(string.ascii_uppercase))
        if include_digits:
            charset += string.digits
            mandatory_chars.append(secrets.choice(string.digits))
        if include_symbols:
            symbols = "!@#$%^&*()-_=+[]{}<>?"
            charset += symbols
            mandatory_chars.append(secrets.choice(symbols))

        if not charset:
            charset = string.ascii_letters + string.digits
            mandatory_chars = [secrets.choice(charset)]

        remaining_length = max(0, length - len(mandatory_chars))
        random_chars = [secrets.choice(charset) for _ in range(remaining_length)]
        combined = mandatory_chars + random_chars

        # Secure shuffle using Fisher-Yates backed by CSPRNG
        for i in range(len(combined) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            combined[i], combined[j] = combined[j], combined[i]

        return "".join(combined)
