//! Reviewed check plan for the managed sts2-game-mod repository.

use super::{ProfilePlan, artifact_check, check, rust_fast, rust_required};

pub(crate) fn managed_profile_plan() -> ProfilePlan {
    let mut required = rust_required();
    required.extend([
                artifact_check("artifact-poc-v1", "protocol-artifact/poc-v1"),
                artifact_check("artifact-runtime-v1", "protocol-artifact/runtime-v1"),
                artifact_check("artifact-runtime-v2", "protocol-artifact/runtime-v2"),
                artifact_check(
                    "artifact-runtime-v3",
                    "protocol-artifact/runtime-v3-gameplay",
                ),
                check(
                    "managed-format",
                    "bash tools/standards/check-managed.sh format",
                    ".",
                ),
                check(
                    "managed-settings",
                    "bash tools/standards/test-managed-settings.sh",
                    ".",
                ),
                check(
                    "managed-abi",
                    "bash tools/standards/test-managed-abi.sh",
                    ".",
                ),
                check(
                    "managed-build",
                    "dotnet build experiments/managed-rust-interop/managed/ManagedInteropSpike.csproj --configuration Release",
                    ".",
                ),
                check(
                    "managed-workshop",
                    "dotnet run --project experiments/managed-rust-interop/workshop/WorkshopValidationProbe.csproj --configuration Release",
                    ".",
                ),
                check(
                    "managed-settings-probe",
                    "dotnet run --project experiments/managed-rust-interop/settings-tests/SettingsValidationProbe.csproj --configuration Release",
                    ".",
                ),
                check(
                    "managed-queue",
                    "dotnet run --project experiments/managed-rust-interop/queue-tests/RuntimeQueueProbe.csproj --configuration Release",
                    ".",
                ),
                check(
                    "managed-runtime-contract",
                    "dotnet run --project experiments/managed-rust-interop/contract-tests/RuntimeContractProbe.csproj --configuration Release",
                    ".",
                ),
                check(
                    "managed-replay",
                    "dotnet run --project experiments/managed-rust-interop/replay-tests/ReplayValidationProbe.csproj --configuration Release",
                    ".",
                ),
                check(
                    "powershell-syntax",
                    "pwsh -NoProfile -NonInteractive -File tools/standards/check-powershell.ps1",
                    ".",
                ),
                check(
                    "powershell-syntax-negative",
                    "pwsh -NoProfile -NonInteractive -File tools/standards/check-powershell.ps1 -SelfTest",
                    ".",
                ),
                check(
                    "managed-process-bridge",
                    "pwsh -NoProfile -NonInteractive -File experiments/managed-rust-interop/dev-cycle-process-tests.ps1",
                    ".",
                ),
                check(
                    "managed-windows-bridge-build",
                    "dotnet build experiments/managed-rust-interop/session-launcher/windows-bridge/SessionWindowsBridge.csproj --configuration Release -warnaserror",
                    ".",
                ),
                check(
                    "managed-windows-bridge-tests",
                    "dotnet run --project experiments/managed-rust-interop/session-launcher/bridge-tests/SessionWindowsBridgeTests.csproj --configuration Release -warnaserror",
                    ".",
                ),
                check(
                    "managed-host-candidate",
                    "dotnet run --project experiments/managed-rust-interop/host-candidate-tests/HostCandidateProbe.csproj --configuration Release",
                    ".",
                ),
                check(
                    "managed-runtime-v3",
                    "dotnet run --project experiments/managed-rust-interop/gameplay-tests/RuntimeV3ValidationProbe.csproj --configuration Release",
                    ".",
                ),
            ]);
    let extended = vec![
        check(
            "managed-session-launcher",
            "bash experiments/managed-rust-interop/session-launcher.test.sh",
            ".",
        ),
        check(
            "managed-session-restore",
            "bash experiments/managed-rust-interop/session-restore.test.sh",
            ".",
        ),
        check(
            "managed-session-bridge",
            "bash experiments/managed-rust-interop/session-bridge.test.sh",
            ".",
        ),
        check(
            "managed-provider-build",
            "bash experiments/managed-rust-interop/provider-build.test.sh",
            ".",
        ),
        check(
            "managed-session-install",
            "bash experiments/managed-rust-interop/session-install.test.sh",
            ".",
        ),
        check(
            "managed-live-authorization",
            "bash experiments/managed-rust-interop/live-authorization.test.sh",
            ".",
        ),
        check(
            "managed-runtime-addon",
            "bash experiments/managed-rust-interop/package-runtime-addon.test.sh",
            ".",
        ),
        check(
            "managed-dev-cycle",
            "bash experiments/managed-rust-interop/dev-cycle.test.sh",
            ".",
        ),
        check(
            "managed-session-self-test",
            "bash experiments/managed-rust-interop/session-launcher.sh --self-test",
            ".",
        ),
        check(
            "managed-workshop-package",
            "bash tools/workshop/test-package-item.sh",
            ".",
        ),
        check(
            "managed-runtime-lifecycle",
            "bash tools/release/test-runtime-lifecycle.sh",
            ".",
        ),
        check(
            "managed-gpu-provision",
            "bash experiments/train-gpu-lifecycle/test-provision.sh",
            ".",
        ),
        check(
            "managed-gpu-boot",
            "bash experiments/train-gpu-lifecycle/test-boot.sh",
            ".",
        ),
    ];
    ProfilePlan {
        scopes: vec!["rust", "csharp", "shell", "powershell", "json", "contracts"],
        fast: rust_fast(false),
        required,
        extended,
    }
}
