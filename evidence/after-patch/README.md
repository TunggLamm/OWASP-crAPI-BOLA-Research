# After-Patch Evidence (Remediated Build)

Screenshots captured after rebuilding and redeploying the patched Identity and Community containers:

1. [`02-client-a-own-vehicle.png`](./02-client-a-own-vehicle.png) — **TC1 (Authorized):** Client A requesting Client A's own vehicle (`1d65151b-a248-4713-ae07-1c481f309d77`) returns `200 OK` with location data.
2. [`03-client-a-other-vehicle.png`](./03-client-a-other-vehicle.png) — **TC2 (Unauthorized BOLA attempt):** Client A requesting Client B's vehicle (`323e8a0f-95cb-448b-a234-9c58c101a9cc`) is blocked with `404 Not Found` (`Sorry we didn't get vehicle for user: `).
3. [`04-community-no-vehicleid.png`](./04-community-no-vehicleid.png) — **Community API Check:** `GET /community/api/v2/community/posts/recent` returns `200 OK` with `vehicleid` and `email` removed from the `author` object.
