# Source patches

Add the actual source-code diffs created by this research here.

Recommended files:

- `identity-service.patch` — changes to the Identity Service authorization flow and repository lookup.
- `community-service.patch` — change to the Community response model that removes `vehicleid`.

Do not write a patch from memory. Generate it by comparing the modified files against the exact original source revision used for the lab. Include the upstream repository URL and source commit/revision in the report.

Before publishing, inspect every diff and remove local secrets, tokens, credentials, machine paths, or unrelated formatting-only changes.
