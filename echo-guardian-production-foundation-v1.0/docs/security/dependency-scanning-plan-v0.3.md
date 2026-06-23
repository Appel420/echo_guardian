# Dependency Scanning Plan v0.3

## Objective

Detect vulnerable, abandoned, or high-risk dependencies before release.

## Required Checks

- Python dependency audit placeholder.
- License review placeholder.
- Native dependency review for iOS and Android once native code is added.
- Fail release gate on critical known vulnerabilities unless explicitly risk-accepted.

## Rule

Dependency scanning is release-gate evidence. It must not upload private source or sensitive user data.
