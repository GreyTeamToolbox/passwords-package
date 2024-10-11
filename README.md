<!-- markdownlint-disable -->
<p align="center">
    <a href="https://github.com/GreyTeamToolbox/">
        <img src="https://cdn.wolfsoftware.com/assets/images/github/organisations/greyteamtoolbox/black-and-white-circle-256.png" alt="GreyTeamToolbox logo" />
    </a>
    <br />
    <a href="https://github.com/GreyTeamToolbox/passwords-package/actions/workflows/cicd.yml">
        <img src="https://img.shields.io/github/actions/workflow/status/GreyTeamToolbox/passwords-package/cicd.yml?branch=master&label=build%20status&style=for-the-badge" alt="Github Build Status" />
    </a>
    <a href="https://github.com/GreyTeamToolbox/passwords-package/blob/master/LICENSE.md">
        <img src="https://img.shields.io/github/license/GreyTeamToolbox/passwords-package?color=blue&label=License&style=for-the-badge" alt="License">
    </a>
    <a href="https://github.com/GreyTeamToolbox/passwords-package">
        <img src="https://img.shields.io/github/created-at/GreyTeamToolbox/passwords-package?color=blue&label=Created&style=for-the-badge" alt="Created">
    </a>
    <br />
    <a href="https://github.com/GreyTeamToolbox/passwords-package/releases/latest">
        <img src="https://img.shields.io/github/v/release/GreyTeamToolbox/passwords-package?color=blue&label=Latest%20Release&style=for-the-badge" alt="Release">
    </a>
    <a href="https://github.com/GreyTeamToolbox/passwords-package/releases/latest">
        <img src="https://img.shields.io/github/release-date/GreyTeamToolbox/passwords-package?color=blue&label=Released&style=for-the-badge" alt="Released">
    </a>
    <a href="https://github.com/GreyTeamToolbox/passwords-package/releases/latest">
        <img src="https://img.shields.io/github/commits-since/GreyTeamToolbox/passwords-package/latest.svg?color=blue&style=for-the-badge" alt="Commits since release">
    </a>
    <br />
    <a href="https://github.com/GreyTeamToolbox/passwords-package/blob/master/.github/CODE_OF_CONDUCT.md">
        <img src="https://img.shields.io/badge/Code%20of%20Conduct-blue?style=for-the-badge" />
    </a>
    <a href="https://github.com/GreyTeamToolbox/passwords-package/blob/master/.github/CONTRIBUTING.md">
        <img src="https://img.shields.io/badge/Contributing-blue?style=for-the-badge" />
    </a>
    <a href="https://github.com/GreyTeamToolbox/passwords-package/blob/master/.github/SECURITY.md">
        <img src="https://img.shields.io/badge/Report%20Security%20Concern-blue?style=for-the-badge" />
    </a>
    <a href="https://github.com/GreyTeamToolbox/passwords-package/issues">
        <img src="https://img.shields.io/badge/Get%20Support-blue?style=for-the-badge" />
    </a>
</p>

## Overview

This script is designed to generate secure passwords and evaluate their strength. It calculates password strength based on entropy, character variety, and rule-based penalties, and includes optional dictionary checks for common passwords. It can also analyze passwords from a file or assess the strength of user-provided passwords.

## Features

- **Password Generation**: Generate random, secure passwords based on customizable character policies.
- **Strength Evaluation**: Check the strength of passwords based on entropy and rule-based criteria.
- **Batch Verification**: Verify the strength of multiple passwords from a file.
- **Custom Dictionary Support**: Use a custom dictionary to check for common or weak passwords.
- **Detailed Reporting**: Get detailed feedback and an estimated crack time for each password on both CPU and GPU.

## Requirements

- **Python** 3.6+
- **tabulate** library: Install via pip

  ```bash
  pip install tabulate
  ```

## Usage

The script provides several options for generating passwords, checking strength, and analyzing passwords from a file. Below are examples of each usage mode.

### 1. Generate Passwords

Generate a specified number of passwords of a given length:

```bash
python password_script.py -l 16 -c 5
```

- `-l`, `--length`: Specify the password length (default: 16).
- `-c`, `--count`: Specify the number of passwords to generate (default: 1).

### 2. Verify a Specific Password

Check the strength of a specific password:

```bash
python password_script.py --verify "YourPassword123!"
```

### 3. Generate and Verify Passwords

Generate passwords and then evaluate their strength:

```bash
python password_script.py -l 16 -c 5 --verify-generated
```

### 4. Verify Passwords from a File

Check the strength of each password listed in a file:

```bash
python password_script.py --file passwords.txt
```

The `passwords.txt` file should contain one password per line.

### 5. Use a Custom Dictionary

Provide a custom dictionary file for password strength checking:

```bash
python password_script.py --verify "password" --dictionary custom_dict.txt
```

### 6. Save Results to a File

Save generated passwords or verification results to a specified file:

```bash
python password_script.py -l 16 -c 5 --verify-generated --save results.txt
```

## Output

The output will display each password's strength information in a table format with the following columns:

- **Password**: The generated or provided password.
- **Strength**: The classification of password strength (Weak, Moderate, Strong, Very Strong).
- **Entropy (bits)**: The calculated entropy of the password.
- **Score**: The password’s strength score.
- **Score (%)**: The percentage of the maximum score achieved.
- **Crack Time (CPU)**: Estimated time to crack the password using a CPU.
- **Crack Time (GPU)**: Estimated time to crack the password using a GPU.

### Example Output

```plaintext
+-------------------------------+-------------+-------------------+----------+-------------+------------------------+-------------------------+
| Password                      | Strength    | Entropy (bits)    | Score    | Score (%)   | Crack Time (CPU)       | Crack Time (GPU)        |
+-------------------------------+-------------+-------------------+----------+-------------+------------------------+-------------------------+
| thisis another random password| Weak        | 141.01            | 50       | 50.00%      | 89.21 septillion years | 892.06 sextillion years |
+-------------------------------+-------------+-------------------+----------+-------------+------------------------+-------------------------+
```

## Configuration

The script's configuration includes default values for password policies and scoring:

- **Password Policies**: Customize policies such as character types (uppercase, lowercase, numbers, special characters), length bonuses, and penalties.
- **Scoring Criteria**: Adjust the scoring based on password length, character variety, entropy, and rule-based penalties.

These settings can be modified in the `Config` class in the script.

## Error Handling

- **File Not Found**: If the specified file or dictionary file cannot be found, a warning is printed, and the script falls back to default settings.
- **Empty Character Set**: If no character type is enabled for password generation, an error is raised.
- **Save Errors**: If an error occurs while saving results, a message is displayed with details about the issue.

<br />
<p align="right"><a href="https://wolfsoftware.com/"><img src="https://img.shields.io/badge/Created%20by%20Wolf%20on%20behalf%20of%20Wolf%20Software-blue?style=for-the-badge" /></a></p>
