# BOLA Security Research – OWASP crAPI

**Project type:** Lab-based API security research  
**Target:** OWASP crAPI (locally deployed)  
**Vulnerability:** Broken Object Level Authorization (BOLA / IDOR)  
**OWASP mapping:** API1:2023 – Broken Object Level Authorization  
**Researcher:** [Your name]  
**Date:** November 2026

## Overview

This project studies a BOLA issue in the vehicle-location API of OWASP crAPI. In the vulnerable implementation, an authenticated user could request a vehicle location using another user's vehicle UUID. The backend looked up the vehicle by UUID but did not enforce that the authenticated user owned that vehicle.

The project covers:

- Discovery of another user's vehicle identifier in Community API response data.
- Reproduction of cross-user access against the Identity vehicle-location endpoint in a local lab.
- Source-code analysis of the Identity controller, service and repository.
- A remediation that constrains the vehicle lookup by both vehicle UUID and authenticated owner ID.
- A Community response data-minimization change that removes the `vehicleid` field from the public author object.
- Verification using authorized and unauthorized cross-user test cases.

> **Scope and honesty note:** This is a lab-based research project against an intentionally vulnerable training application. It is not a claim of finding a previously unknown vulnerability in a production system. Add only evidence and test results that you personally captured and verified.

## Vulnerability summary

**Affected endpoint**

```http
GET /identity/api/v2/vehicle/{carId}/location
```

**Root cause:** The vulnerable service retrieved a vehicle using only the client-supplied UUID. It retrieved the vehicle owner's information for the response, but did not compare the owner with the authenticated user before returning the data.

**Impact demonstrated in the lab:** Unauthorized disclosure of another test user's vehicle location and associated owner details.

## Remediation summary

The Identity Service lookup was changed to require both the requested vehicle UUID and the authenticated user's ID. The current user must come from the application's validated authentication context/token, not from a client-controlled request field.

The Community Service response was also changed to omit the `vehicleid` field from public author data. This is defense-in-depth/data minimization only; it does **not** replace the Identity Service authorization check.

## Repository structure

```text
report/       Technical report
 evidence/    Sanitized screenshots and HTTP evidence
 patches/     Source-code diffs for the changes
 tests/       Regression-test matrix and observed results
```

## Evidence status

- `evidence/after-patch/`: add the screenshots and sanitized HTTP captures from the patched implementation.
- `evidence/before-patch/`: leave this pending until the original vulnerable image has been safely reconstructed and tested. Do not fabricate or backdate screenshots.
- `tests/regression-test-results.md`: enter the exact observed status codes and observations from Burp Repeater.

## Tools

- OWASP crAPI
- Docker Desktop / Docker Compose
- Burp Suite Community Edition
- Java / Spring Boot (Identity Service)
- Go (Community Service)
- Git / GitHub

## References

- OWASP crAPI: https://owasp.org/www-project-crAPI/
- OWASP crAPI repository: https://github.com/OWASP/crAPI
- OWASP API Security Top 10 – API1:2023: https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/

## Responsible presentation

This repository documents a controlled local lab exercise. Do not include JWTs, cookies, passwords, private keys, `.env` secrets, database dumps, or real personal data. Redact authorization headers in all screenshots and request samples.
