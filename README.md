# BOLA Security Research – OWASP crAPI

**Project type:** Lab-based API security research  
**Target:** OWASP crAPI (locally deployed)  
**Vulnerability:** Broken Object Level Authorization (BOLA / IDOR)  
**OWASP mapping:** API1:2023 – Broken Object Level Authorization  
**Researcher:** Khieu Tung Lam  
**Date:** November 2026

## Overview

This project studies a BOLA issue in the vehicle-location API of OWASP crAPI (`GET /identity/api/v2/vehicle/{carId}/location`). In the vulnerable implementation, an authenticated user could request a vehicle location using another user's vehicle UUID. The backend looked up the vehicle by UUID alone without verifying that the authenticated user owned that vehicle.

The project covers:

- Discovery of other users' vehicle identifiers (`vehicleid`) leaked in Community API responses (`GET /community/api/v2/community/posts/recent`).
- Reproduction of cross-user BOLA access against the Identity vehicle-location endpoint in a local lab.
- Source-code root cause analysis of the Identity controller/service (`Java / Spring Boot`) and Community model (`Go`).
- Primary remediation in the Identity Service verifying that the authenticated user owns the requested vehicle (`vehicleDetails.getOwner().getId().equals(user.getId())`).
- Defense-in-depth data minimization in the Community Service omitting `vehicleid` and `email` from public post author responses.
- Verification using Burp Suite Repeater across authorized and unauthorized test cases.

## Repository Structure

```text
report/       Technical report (report/technical-report.md)
evidence/     Before-patch and after-patch Burp Suite screenshots
patches/      Unified diffs for Identity Service and Community Service
tests/        Regression test results (tests/regression-test-results.md)
```

## Quick Links

- **Technical Report:** [`report/technical-report.md`](./report/technical-report.md)
- **Patches:** [`patches/identity-service.patch`](./patches/identity-service.patch) | [`patches/community-service.patch`](./patches/community-service.patch)
- **Evidence (Before Patch):** [`evidence/before-patch/`](./evidence/before-patch/README.md)
- **Evidence (After Patch):** [`evidence/after-patch/`](./evidence/after-patch/README.md)
- **Regression Test Matrix:** [`tests/regression-test-results.md`](./tests/regression-test-results.md)

## Tools Used

- OWASP crAPI
- Docker Desktop / Docker Compose
- Burp Suite Community Edition
- Java / Spring Boot (Identity Service)
- Go (Community Service)

## References

- OWASP crAPI: https://owasp.org/www-project-crAPI/
- OWASP crAPI repository: https://github.com/OWASP/crAPI
- OWASP API Security Top 10 – API1:2023: https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
