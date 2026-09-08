# Web and PHP profile guidance

Static HTML/CSS/vanilla JavaScript sites, PHP endpoints, and their development-only tooling keep
their existing runtime architecture. This profile does not authorize a framework rewrite,
TypeScript migration, bundler, or dependency change.

## PHP boundary

`aiascension.tech` declares production PHP `>=8.1` and PHPUnit `^11`, whose supported runtime
requires PHP >=8.2. Keep that compatibility split visible: either run the test lane on a supported
PHP version or record the owner-approved alignment before changing a deployment minimum. Use
Composer's lockfile and the selected coding-style/static-analysis tool at pinned versions; never
adopt an unqualified latest major.

Validate request method, JSON shape, scalar types, body and field limits before side effects.
Origin membership is an exact parsed scheme/host/effective-port allowlist with deliberate
missing-Origin semantics. Raw string suffix checks, malformed/opaque origins, invalid schemes or
ports, and lookalike hosts must be rejected. CORS is not authentication.

Serialize the complete subscriber/rate-limit read-modify-write operation under the existing lock.
Test duplicate calls, increments, corrupt data, failed writes, interruptions, barriers, and
bounded lock waits. Distinguish process isolation, atomic replacement, and durability. Map raw
exceptions to safe event/error classes and test synthetic secret markers; never claim a leak from
a source finding alone.

## Browser and static checks

Use the site's existing Node test context for deterministic DOM checks, and separately exercise
real browser keyboard/focus, error, reduced-motion, and responsive behavior where the site claims
it. Keep fixtures and test reports out of production artifacts. Static recipes remain pinned to
their exact source revision and checksum. A successful Node test does not establish a deployed
site, host PHP extensions, mail delivery, or live subscriber behavior.
