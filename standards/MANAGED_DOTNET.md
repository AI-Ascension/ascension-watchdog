# Managed and native boundary guidance

The managed exception belongs only to `sts2-game-mod`'s loader, host probes, and source-only
supporting tests. It does not make the other Rust repositories managed projects and does not
redistribute `sts2.dll`, `GodotSharp.dll`, a game binary, a save, or a host assembly.

## Evaluated configuration

Inspect the project that will actually build. Record target framework, nullable/analyzer settings,
warnings-as-errors, deterministic build settings, language version, package references, and
editor formatting. `Directory.Build.props` parity is not proof that a C# project exists. The
current source-only managed lane uses .NET SDK 9.0.317; the Windows bridge includes a net8.0
project. Keep that split explicit until its owner approves alignment.

The source-only checks are:

```text
dotnet build experiments/managed-rust-interop/managed/ManagedInteropSpike.csproj --configuration Release
dotnet run --project experiments/managed-rust-interop/workshop/WorkshopValidationProbe.csproj --configuration Release
```

Run the target's additional source-linked probes when they exist. A build or synthetic probe is
source/build evidence only. The exact-host loader build requires an operator-supplied host
installation and is a separately recorded, authorized compatibility check.

## ABI and host rules

Use fixed-width values, explicit encoding, versioned descriptors, allocator ownership, callback
retention, unload order, and a documented main-thread boundary. Convert host objects into owned
values before crossing a thread or process boundary. Keep bounded queue admission and settled
results visible in tests. Preserve exact host spellings such as
`MegaCrit.Sts2.Core.Modding.ModInitializer`, `sts2.dll`, and host-required JSON members.

Do not use a fake host or a native compile to claim host discovery, load success, thread safety,
gameplay, or release compatibility. Mark unavailable host SDKs and assemblies `unverified` with
the exact missing prerequisite.
