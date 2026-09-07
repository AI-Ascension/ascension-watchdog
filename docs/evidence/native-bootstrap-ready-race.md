# P8 parent-descriptor readiness race

Classification: source-derived blocker in candidate `25bfdfa`; not integrated.

The candidate keeps bootstrap descriptors CLOEXEC and opens them from the
parent's proc-fd view, but drops `parent_bootstrap` in `PendingLaunch::into_child`
immediately after the write-only GO barrier. `prepare` writes the request frame
to anonymous stdin and `release_gate` writes GO; neither receives a helper
acknowledgment. A bounded small frame can be buffered while the helper has not
yet run `parse_helper_bootstrap`.

Thus the parent's descriptors may close before the helper opens them. The
numeric descriptors may then be absent or reused. The comment that the helper
must parse before accepting GO is insufficient: writing GO does not prove its
acceptance or consumption.

Requested repair: retain exact descriptors until a bounded nonce-bound readiness
acknowledgment proves they were opened, or transfer their lifetime to an exact
owned-child authority without leaking them across target exec. Add a deliberately
delayed-helper regression. Normal scheduling and portable CLOEXEC checks alone
do not exercise this race.
