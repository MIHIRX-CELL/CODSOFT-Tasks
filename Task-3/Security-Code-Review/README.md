# CODSOFT Task 3 - Security Code Review

## Project Title

Secure Notes - Security Code Review and Secure Coding Improvement

## Objective

The objective of this task is to examine an application source code, identify common security weaknesses and coding flaws, perform static and manual security analysis, and implement secure coding improvements.

## Application Description

Secure Notes is a small educational web application developed using Python Flask and SQLite.

The application provides:

- User registration
- User login and logout
- Session-based authentication
- Personal note creation
- Note viewing
- Note deletion
- SQLite database storage

The application was intentionally reviewed in two stages:

1. Vulnerable version
2. Secure version

The vulnerable version was used for identifying security weaknesses, while the secure version contains recommended fixes.

## Technology Used

- Python
- Flask
- SQLite
- HTML
- CSS
- Werkzeug Security
- Bandit Static Code Analyzer
- Kali Linux

## Security Review Methodology

The security review used:

- Static analysis using Bandit
- Manual source code review
- Comparison between vulnerable and secure implementations
- Functional testing of the application

Testing was performed in a local educational environment.

## Vulnerabilities Identified

The following security weaknesses were identified during the review:

1. Hardcoded Flask Secret Key
2. SQL Injection Risk
3. Flask Debug Mode Enabled
4. Plaintext Password Storage
5. Missing Input Validation
6. Missing CSRF Protection
7. Missing Security Headers
8. Lack of Login Rate Limiting

## Bandit Static Analysis

### Before Security Fixes

Bandit identified the following issues:

- B105 - Hardcoded password/secret string
- B608 - Hardcoded SQL expression
- B201 - Flask debug mode enabled

### After Security Fixes

Bandit was executed again after implementing secure coding improvements.

Result:

`No issues identified.`

## Secure Coding Improvements

The secure version implements:

- Environment-based secret configuration
- Password hashing using Werkzeug
- Parameterized SQL queries
- Input validation
- Secure session cookie configuration
- Security response headers
- Content Security Policy
- Disabled Flask debug mode
- Session clearing during authentication
- Authorization checks for note deletion

## Project Structure

```text
Security-Code-Review/
├── vulnerable_app/
├── vulnerable_app_original/
├── secure_app/
├── reports/
│   ├── bandit-before.txt
│   ├── bandit-before.json
│   ├── bandit-after.txt
│   └── bandit-after.json
├── screenshots/
└── README.md

