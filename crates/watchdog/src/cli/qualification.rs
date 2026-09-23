//! Native qualification verification and synthetic evidence writing.
use super::take_option;
use crate::error::{Result, WatchdogError};
use std::path::Path;

pub(super) fn qualification_command(args: &mut Vec<String>) -> Result<Option<String>> {
    let operation = args.first().cloned().ok_or_else(|| {
        WatchdogError::InvalidInput(
            "qualification requires verify-native or write-synthetic".to_owned(),
        )
    })?;
    args.remove(0);
    match operation.as_str() {
        "verify-native" => {
            let evidence = take_option(args, "--evidence").ok_or_else(|| {
                WatchdogError::InvalidInput(
                    "qualification verify-native requires --evidence".to_owned(),
                )
            })?;
            let revision = take_option(args, "--expected-source-revision").ok_or_else(|| {
                WatchdogError::InvalidInput(
                    "qualification verify-native requires --expected-source-revision".to_owned(),
                )
            })?;
            let receipt = take_option(args, "--receipt").ok_or_else(|| {
                WatchdogError::InvalidInput(
                    "qualification verify-native requires --receipt".to_owned(),
                )
            })?;
            if !args.is_empty() {
                return Err(WatchdogError::InvalidInput(
                    "unexpected qualification verify-native argument".to_owned(),
                ));
            }
            let report = crate::qualification::verify_native_document(
                Path::new(&evidence),
                Path::new(&receipt),
                &revision,
            )
            .map_err(WatchdogError::InvalidInput)?;
            let output = serde_json::to_string(&report)?;
            if report.qualified_native {
                Ok(Some(output))
            } else {
                Err(WatchdogError::VerificationFailed(output))
            }
        }
        "write-synthetic" => {
            let revision = take_option(args, "--source-revision").ok_or_else(|| {
                WatchdogError::InvalidInput(
                    "qualification write-synthetic requires --source-revision".to_owned(),
                )
            })?;
            let os = take_option(args, "--os").ok_or_else(|| {
                WatchdogError::InvalidInput(
                    "qualification write-synthetic requires --os".to_owned(),
                )
            })?;
            let output = take_option(args, "--output").ok_or_else(|| {
                WatchdogError::InvalidInput(
                    "qualification write-synthetic requires --output".to_owned(),
                )
            })?;
            let receipt_sha256 = take_option(args, "--receipt-sha256").ok_or_else(|| {
                WatchdogError::InvalidInput(
                    "qualification write-synthetic requires --receipt-sha256".to_owned(),
                )
            })?;
            if !args.is_empty() {
                return Err(WatchdogError::InvalidInput(
                    "unexpected qualification write-synthetic argument".to_owned(),
                ));
            }
            let document =
                crate::qualification::synthetic_evidence(&revision, &os, &receipt_sha256)
                    .map_err(WatchdogError::InvalidInput)?;
            std::fs::write(output, document.as_bytes())?;
            Ok(Some(document))
        }
        _ => Err(WatchdogError::InvalidInput(
            "qualification requires verify-native or write-synthetic".to_owned(),
        )),
    }
}
