# Before-Patch Evidence (Vulnerable Baseline)

Screenshots captured on the unmodified OWASP crAPI deployment demonstrating the vulnerability chain:

1. [`01-community-response.png`](./01-community-response.png) — `GET /community/api/v2/community/posts/recent` returning `200 OK` and exposing `vehicleid` and `email` inside each post's `author` object.
2. [`02-bola-vehicle-location-poc.png`](./02-bola-vehicle-location-poc.png) — BOLA Proof of Concept: Client A's authenticated session requesting Client B's vehicle (`GET /identity/api/v2/vehicle/323e8a0f-95cb-448b-a234-9c58c101a9cc/location`) and receiving `200 OK` with Client B's GPS coordinates and personal info.
