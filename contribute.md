# Contributing to AuthNexus

We welcome contributions from the community. Please follow these guidelines to ensure smooth collaboration.

## Table of Contents
1. [Code of Conduct](#code-of-conduct)
2. [Bug Reports](#bug-reports)
3. [Feature Requests](#feature-requests)
4. [Development Setup](#development-setup)
5. [Coding Standards](#coding-standards)
6. [Testing](#testing)
7. [Pull Requests](#pull-requests)
8. [Security Practices](#security-practices)

## Code of Conduct
This project adheres to the [Contributor Covenant](CODE_OF_CONDUCT.md). By participating, you agree to uphold its terms.

## Bug Reports
1. Check existing issues to avoid duplicates
2. Use the bug report template:
**Describe the bug**  
Clear description of unexpected behavior

**Reproduction Steps**  
1. Environment details (OS/Python version)
2. Code snippet to reproduce
3. Error message/traceback

**Expected Behavior**  
Concise description of expected outcome

**Screenshots**  
If applicable

**Additional Context**  
Any relevant information
Feature Requests
Check roadmap in documentation

Use feature request template:
**Problem Statement**  
Clear description of use case

**Proposed Solution**  
Detailed feature description

**Alternatives Considered**  
Other approaches evaluated

**Additional Context**  
Relevant references/examples
Development Setup
Fork and clone the repository

Create virtual environment:
python -m venv .venv
source .venv/bin/activate
Install dependencies:
pip install -e .[dev,security]
pre-commit install
Configure environment variables:
export AUTH_SECRET=$(openssl rand -hex 32)
Coding Standards
Style Guidelines

Follow PEP 8 with line length 100

Type hints required for all new code

Docstrings follow Google style guide

Commit Messages

Use Conventional Commits specification

Format: <type>(<scope>): <description>

Example: feat(auth): add WebAuthn registration flow

Documentation

Update relevant sections in /docs

Add module-level docstrings

Keep comments focused on "why" not "what"
Pull Requests
Branch Naming

Feature: feature/<short-description>

Bugfix: fix/<issue-number>

PR Requirements

Link related issues

Pass all CI checks

Maintain 95%+ test coverage

Update documentation

Review Process

Two maintainer approvals required

Security review for sensitive changes

48-hour response target

Security Practices
Never include secrets in code

Use EnvVault for configuration

Validate all third-party dependencies

Follow SECURITY.md for vulnerabilities

Licensing
By contributing, you agree to license your work under the project's AGPL-3.0 license.

Thank you for considering contributing to AuthNexus! For questions, contact satwikmishra46@gmail.com

