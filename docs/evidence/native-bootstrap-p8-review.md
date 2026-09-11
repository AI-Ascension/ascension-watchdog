# P8 bootstrap descriptor review

Classification: source-derived blocker; candidate `a64b017` not integrated.

The candidate opens the protected configuration and delegated cgroup directory
before helper launch. However, its descriptor lifecycle does not yet enforce
the claimed helper-only inheritance:

1. `inherited_descriptors` clears `CLOEXEC` on cloned parent descriptors.
2. `from_inherited_fds` reopens those descriptors through `/proc/self/fd` but
   neither closes nor restores `CLOEXEC` on the original inherited descriptors.
3. `run_hidden_helper_core` reaches `spawn_authorized_target` with those original
   descriptors still inheritable. Reopening a descriptor creates another handle;
   it does not consume the original descriptor.

Consequently the protected configuration and delegated-root descriptors can
survive target exec. The parent also has a temporarily inheritable descriptor
window during which concurrent child launches may receive those handles.

Returned to P8 for explicit ownership and inheritance lifecycle repair. Required
regression: inspect target-visible descriptors and prove bootstrap handles are
absent after successful exec, with bounded cleanup on failure. Do not infer
descriptor isolation from environment clearing or from a successful build.

The separate Windows durable-intent generation binding remains a root integration
requirement. This review does not claim its completion or native service evidence.
