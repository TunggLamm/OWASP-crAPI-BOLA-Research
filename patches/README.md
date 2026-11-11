# Source Patches

This directory contains the unified diff patches representing the source-code remediations implemented during this research against [OWASP crAPI](https://github.com/OWASP/crAPI).

## Included patches

- [`identity-service.patch`](./identity-service.patch) — Enforces object-level authorization in the Identity Service (`VehicleController.java`, `VehicleService.java`, and `VehicleServiceImpl.java`) by extracting the authenticated user from the request JWT via `userService.getUserFromToken(request)` and verifying that `vehicleDetails.getOwner().getId().equals(user.getId())` before returning vehicle location data.
- [`community-service.patch`](./community-service.patch) — Applies data minimization in the Community Service (`services/community/api/models/user.go`) by excluding `email` and `vehicleid` from public JSON/BSON serialization of `Author` objects and removing the unnecessary `vehicle_details` UUID query in `FindAuthorByEmail`.

## Applying the patches

From the root of an unmodified OWASP crAPI source tree:

```bash
git apply patches/identity-service.patch
git apply patches/community-service.patch
```
