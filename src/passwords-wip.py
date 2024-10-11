"""
Password Generator and Strength Checker.

This script generates secure passwords and evaluates their strength using entropy, character variety,
rule-based penalties, and optional dictionary checks. It can also assess the strength of user-provided
passwords based on these criteria.

Usage:
    - Generate passwords:
        python password_script.py -l 16 -c 5
    - Verify the strength of a specific password:
        python password_script.py --verify "YourPassword123!"
    - Generate and verify strength of generated passwords:
        python password_script.py -l 16 -c 5 --verify-generated
    - Verify passwords from a file:
        python password_script.py --file passwords.txt
    - Use a custom dictionary for strength checks:
        python password_script.py --verify "password" --dictionary custom_dict.txt

Dependencies:
    - tabulate: Install via `pip install tabulate`
"""

import string
import argparse
import math
import re
import secrets
from typing import Any, List, Tuple, Dict, Optional, Set
from tabulate import tabulate


class Config:  # pylint: disable=too-few-public-methods
    """Configuration class to manage default settings and policies."""

    MAX_SCORE = 100
    DEFAULT_DICTIONARY: Set[str] = {"password", "123456", "123456789", "12345", "12345678", "qwerty", "abc123", "password1"}

    DEFAULT_POLICY: Dict[str, Any] = {
        "length": 16,
        "count": 1,
        "use_uppercase": True,
        "use_lowercase": True,
        "use_numbers": True,
        "use_special": True,
        "no_repeats": False,
        "avoid_ambiguous": False
    }

    DEFAULT_CONFIG: Dict[str, Dict[str, int]] = {
        "length_bonus": {"min_length_8": 10, "min_length_12": 20, "min_length_16": 30, "min_length_20": 40},
        "character_variety": {"lowercase": 5, "uppercase": 5, "digits": 5, "special": 5},
        "entropy_bonus": {"low_entropy": 10, "medium_entropy": 20, "high_entropy": 30, "very_high_entropy": 40},
        "penalty": {"simple_sequence": -20, "keyboard_pattern": -15}
    }


def load_custom_dictionary(file_path: Optional[str]) -> Set[str]:
    """
    Load a custom dictionary file for password checks.

    Fallback to the default dictionary if not provided or unavailable.

    Arguments:
        file_path (Optional[str]): Path to a custom dictionary file.

    Returns:
        Set[str]: A set of words for password checks.
    """
    if not file_path:
        return Config.DEFAULT_DICTIONARY
    try:
        with open(file_path, 'r', encoding="utf-8") as f:
            return {line.strip() for line in f}
    except FileNotFoundError:
        print("Warning: Custom dictionary file not found. Using default dictionary.")
        return Config.DEFAULT_DICTIONARY
    except IOError as e:
        print(f"Error: Unable to read dictionary file: {e}")
        return Config.DEFAULT_DICTIONARY


def calculate_entropy(password: str) -> float:
    """
    Calculate the entropy of a password based on its character variety and length.

    Arguments:
        password (str): Password to analyze.

    Returns:
        float: Entropy of the password.
    """
    char_space = 0
    if any(c.islower() for c in password):
        char_space += 26
    if any(c.isupper() for c in password):
        char_space += 26
    if any(c.isdigit() for c in password):
        char_space += 10
    if any(c in string.punctuation for c in password):
        char_space += 32
    return len(password) * math.log2(char_space) if char_space > 0 else 0


def calculate_crack_time(entropy: float, guesses_per_second: float) -> str:
    """
    Estimate the time required to crack the password based on entropy and guess rate.

    Arguments:
        entropy (float): Entropy of the password.
        guesses_per_second (float): Rate of guessing attempts per second.

    Returns:
        str: Estimated crack time in human-readable format.
    """
    total_combinations: float = 2 ** entropy
    seconds: float = total_combinations / guesses_per_second
    units: List = [
        ("seconds", 60), ("minutes", 60), ("hours", 24), ("days", 365), ("years", 1000),
        ("thousand years", 1e3), ("million years", 1e3), ("billion years", 1e3),
        ("trillion years", 1e3), ("quadrillion years", 1e3), ("quintillion years", 1e3),
        ("sextillion years", 1e3), ("septillion years", 1e3), ("octillion years", 1e3),
        ("nonillion years", 1e3), ("decillion years", 1e3), ("undecillion years", 1e3),
        ("duodecillion years", 1e3), ("tredecillion years", 1e3), ("quattuordecillion years", 1e3),
        ("quindecillion years", 1e3), ("sexdecillion years", 1e3), ("septendecillion years", 1e3),
        ("octodecillion years", 1e3), ("novemdecillion years", 1e3), ("vigintillion years", 1e3)
    ]

    for unit, factor in units:
        if seconds < factor:
            return f"{seconds:.2f} {unit}"  # noqa
        seconds /= factor

    return f"{seconds:.2f} vigintillion years"  # noqa


def build_charset(policy: Dict[str, bool]) -> str:
    """
    Build a character set for password generation based on the specified policy.

    Arguments:
        policy (Dict[str, bool]): Password policy defining allowed character types.

    Returns:
        str: String containing allowed characters for password generation.
    """
    charset: str = ""
    ambiguous_chars = "O0Il1"
    if policy["use_uppercase"]:
        charset += string.ascii_uppercase
    if policy["use_lowercase"]:
        charset += string.ascii_lowercase
    if policy["use_numbers"]:
        charset += string.digits
    if policy["use_special"]:
        charset += string.punctuation
    if policy["avoid_ambiguous"]:
        charset = ''.join(c for c in charset if c not in ambiguous_chars)
    if not charset:
        raise ValueError("Character set cannot be empty. Enable at least one character type.")
    return charset


def check_character_variety(password: str, config: Dict) -> int:
    """
    Calculate the character variety score based on the inclusion of different character types.

    Arguments:
        password (str): Password to evaluate.
        config (Dict): Configuration for scoring.

    Returns:
        int: Character variety score.
    """
    variety_score = 0
    if re.search(r"[a-z]", password):
        variety_score += config["character_variety"]["lowercase"]
    if re.search(r"[A-Z]", password):
        variety_score += config["character_variety"]["uppercase"]
    if re.search(r"[0-9]", password):
        variety_score += config["character_variety"]["digits"]
    if re.search(r"[!@#$%^&*()_+=\-{}\[\]:;'\"|\\,.<>/?]", password):
        variety_score += config["character_variety"]["special"]
    return variety_score


def apply_rule_based_penalties(password: str, config: Dict) -> int:
    """
    Apply rule-based penalties for common password patterns and simple sequences.

    Arguments:
        password (str): Password to evaluate.
        config (Dict): Configuration for penalty scoring.

    Returns:
        int: Total penalty for rule-based patterns.
    """
    penalty = 0
    for sequence in ["123", "abcd", "password", "qwerty", "asdf"]:
        if sequence in password:
            penalty += config["penalty"]["simple_sequence"]
            break
    for pattern in ["qwerty", "asdf", "zxcv", "1234", "password"]:
        if pattern in password:
            penalty += config["penalty"]["keyboard_pattern"]
            break
    return penalty


def generate_password(length: int, charset: str, no_repeats: bool) -> Tuple[str, float]:
    """
    Generate a random password of the specified length using the provided character set.

    Arguments:
        length (int): Desired length of the password.
        charset (str): Character set for generating the password.
        no_repeats (bool): Flag to avoid consecutive repeated characters.

    Returns:
        Tuple[str, float]: Generated password and its entropy.
    """
    password: List = []
    while len(password) < length:
        next_char: str = secrets.choice(charset)
        if no_repeats and password and next_char == password[-1]:
            continue
        password.append(next_char)
    password_str: str = ''.join(password)
    return password_str, calculate_entropy(password_str)


def password_strength(password: str, config: Dict, custom_dict: Optional[Set[str]] = None) -> Tuple[str, float, float, float, str, str, List[str]]:
    """
    Assess the strength of a password and provide recommendations for improvement.

    Arguments:
        password (str): Password to assess.
        config (Dict): Configuration for scoring.
        custom_dict (Optional[Set[str]]): Custom dictionary for strength checks.

    Returns:
        Tuple[str, float, float, float, str, str, List[str]]: Password strength analysis.
    """
    entropy: float = calculate_entropy(password)
    variety_score: int = check_character_variety(password, config)
    feedback: List = []

    # Check if the password is in the dictionary, if so set score to 0
    if password in (custom_dict or Config.DEFAULT_DICTIONARY):
        feedback.append("This password is too common and easily guessable. Choose a more unique password.")
        return "Weak", entropy, 0, 0, "Instantly", "Instantly", feedback

    score: int = variety_score + get_length_bonus(password, config) + get_entropy_bonus(entropy, config)
    score += apply_rule_based_penalties(password, config)

    # Finalize score and calculate crack time
    score = max(score, 0)
    score_percentage: float = min((score / Config.MAX_SCORE) * 100, 100)
    cpu_crack_time: str = calculate_crack_time(entropy, 1e9)
    gpu_crack_time: str = calculate_crack_time(entropy, 1e11)
    strength: str = classify_strength(entropy, gpu_crack_time)

    return strength, entropy, score, score_percentage, cpu_crack_time, gpu_crack_time, feedback


def get_length_bonus(password: str, config: Dict) -> int:
    """
    Calculate the length bonus.

    Arguments:
        password (str): Password to evaluate.
        config (Dict): Configuration for length bonus.

    Returns:
        int: Length bonus score.
    """
    if len(password) >= 20:
        return config["length_bonus"]["min_length_20"]
    if len(password) >= 16:
        return config["length_bonus"]["min_length_16"]
    if len(password) >= 12:
        return config["length_bonus"]["min_length_12"]
    if len(password) >= 8:
        return config["length_bonus"]["min_length_8"]
    return 0


def get_entropy_bonus(entropy: float, config: Dict) -> int:
    """
    Calculate an entropy bonus based on the entropy value.

    Arguments:
        entropy (float): Entropy of the password.
        config (Dict): Configuration for entropy bonus.

    Returns:
        int: Entropy bonus score.
    """
    if entropy >= 100:
        return config["entropy_bonus"]["very_high_entropy"]
    if entropy >= 80:
        return config["entropy_bonus"]["high_entropy"]
    if entropy >= 60:
        return config["entropy_bonus"]["medium_entropy"]
    return config["entropy_bonus"]["low_entropy"]


def classify_strength(entropy: float, gpu_crack_time: str) -> str:
    """
    Classify the strength of the password based on entropy and patterns.

    Arguments:
        entropy (float): Entropy of the password.
        gpu_crack_time (str): Estimated crack time on GPU.

    Returns:
        str: Password strength classification.
    """
    if any(entry in gpu_crack_time for entry in ["days", "hours", "minutes", "seconds"]):
        return "Weak"
    if entropy >= 80:
        return "Very Strong"
    if entropy >= 65:
        return "Strong"
    if entropy >= 50:
        return "Moderate"
    return "Weak"


def display_results(passwords: List[Tuple[str, str, float, float, float, str, str]]):
    """
    Display the strength analysis of passwords in a tabular format.

    Arguments:
        passwords (List[Tuple[str, str, float, float, float, str, str]]): List of password strength analysis.
    """
    headers: List[str] = ["Password", "Strength", "Entropy (bits)", "Score", "Score (%)", "Crack Time (CPU)", "Crack Time (GPU)"]
    table_data: List[Tuple[str]] = [
        (pw, strength, f"{entropy:.2f}", f"{score:.2f}", f"{score_percentage:.2f}%", cpu_time, gpu_time)  # noqa
        for pw, strength, entropy, score, score_percentage, cpu_time, gpu_time in passwords
    ]
    print(tabulate(table_data, headers=headers, tablefmt="grid"))


def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments.

    Returns:
        argparse.Namespace: Parsed arguments.
    """
    parser = argparse.ArgumentParser(description="Generate secure passwords or verify strength.")
    parser.add_argument("-l", "--length", type=int, default=Config.DEFAULT_POLICY["length"], help="Password length.")
    parser.add_argument("-c", "--count", type=int, default=Config.DEFAULT_POLICY["count"], help="Number of passwords to generate.")
    parser.add_argument("--verify", type=str, help="Verify the strength of a provided password.")
    parser.add_argument("--verify-generated", action="store_true", help="Generate and verify the strength of each password.")
    parser.add_argument("--dictionary", type=str, help="Path to a custom dictionary file for strength testing.")
    parser.add_argument("--file", type=str, help="File containing passwords to verify.")
    parser.add_argument("--save", type=str, help="File to save generated passwords and results.")
    return parser.parse_args()


def verify_password_file(file_path: str, config: Dict, custom_dict: Optional[Set[str]]):
    """
    Verify the strength of each password in a file.

    Arguments:
        file_path (str): Path to the file containing passwords.
        config (Dict): Configuration for scoring.
        custom_dict (Optional[Set[str]]): Custom dictionary for strength checks.
    """
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            passwords: List[str] = [line.strip() for line in file.readlines()]
            results: List[Tuple[str | float]] = [(pw, *password_strength(pw, config, custom_dict)[:-1]) for pw in passwords]
            display_results(results)
    except FileNotFoundError:
        print(f"Error: File {file_path} not found.")
    except IOError as e:
        print(f"Error reading file {file_path}: {e}")


def main() -> None:  # noqa
    """
    Main function to execute the password manager.
    """
    args: argparse.Namespace = parse_arguments()
    custom_dict: Set[str] = load_custom_dictionary(args.dictionary)

    if args.verify:
        result: Tuple[str | float | List[str]] = password_strength(args.verify, Config.DEFAULT_CONFIG, custom_dict)
        display_results([(args.verify, *result[:-1])])
        if result[-1]:  # Print feedback
            print("\nSuggestions to strengthen your password:")
            for suggestion in result[-1]:
                print(f"- {suggestion}")
    elif args.file:
        verify_password_file(args.file, Config.DEFAULT_CONFIG, custom_dict)
    else:
        charset: str = build_charset(Config.DEFAULT_POLICY)
        passwords: List[Tuple[str | float]] = [generate_password(args.length, charset, Config.DEFAULT_POLICY["no_repeats"]) for _ in range(args.count)]
        if args.verify_generated:
            results: List[Tuple[str | float]] = [(pw, *password_strength(pw, Config.DEFAULT_CONFIG, custom_dict)[:-1]) for pw, _ in passwords]
            display_results(results)
        else:
            print("\nGenerated Passwords:")
            for idx, (password, _) in enumerate(passwords, 1):
                print(f"{idx}. {password}")

        if args.save:
            try:
                with open(args.save, "w", encoding="utf-8") as file:
                    if args.verify_generated:
                        file.write(tabulate(
                            [(pw, *password_strength(pw, Config.DEFAULT_CONFIG, custom_dict)[:-1]) for pw, _ in passwords],
                            headers=["Password", "Strength", "Entropy (bits)", "Score", "Score (%)", "Crack Time (CPU)", "Crack Time (GPU)"]
                        ))
                    else:
                        file.write("\n".join(pw for pw, _ in passwords))
            except IOError as e:
                print(f"Error saving to file {args.save}: {e}")


if __name__ == "__main__":
    main()
