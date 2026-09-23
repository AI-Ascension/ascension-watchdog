//! Exception document validation for profile review evidence.

use crate::Result;
use crate::dates::{date_days, valid_date, valid_date_order};
use crate::identifiers::{
    ordinary_style_rule, unique, valid_exception_id, valid_relative_path, valid_review_url,
    valid_rule_id,
};
use crate::model::{Exception, Profile};
use crate::parsing::parse_yaml;
use crate::paths::{require_regular_file, safe_join};
use std::collections::BTreeMap;
use std::path::Path;

pub(crate) fn validate_profile_exception(
    root: &Path,
    profile: &Profile,
    rule_ids: &BTreeMap<String, bool>,
    as_of: i64,
    allow_fixture_review: bool,
) -> Result<()> {
    if profile.exceptions.status == "none" {
        return Ok(());
    }
    let path = safe_join(root, &profile.exceptions.file)?;
    require_regular_file(&path)?;
    let exception = parse_yaml::<Exception>(&path)?;
    validate_exception(&exception, Some(rule_ids), as_of, allow_fixture_review)
}

pub(crate) fn validate_exception(
    exception: &Exception,
    known_rule_ids: Option<&BTreeMap<String, bool>>,
    as_of: i64,
    allow_fixture_review: bool,
) -> Result<()> {
    if !valid_exception_id(&exception.id)
        || exception.rule_ids.is_empty()
        || !unique(&exception.rule_ids)
        || exception.paths.is_empty()
        || !unique(&exception.paths)
        || exception.owner.trim().is_empty()
        || exception.rationale.trim().len() < 20
        || exception.compensating_tests.is_empty()
        || exception
            .compensating_tests
            .iter()
            .any(|test| test.trim().is_empty())
        || exception.approval.reviewer.trim().is_empty()
        || exception.approval.status != "approved"
        || !valid_date(&exception.reviewed_on)
        || !valid_date(&exception.expires_on)
        || !valid_date_order(&exception.reviewed_on, &exception.expires_on)
        || date_days(&exception.expires_on)? < as_of
        || date_days(&exception.reviewed_on)? > as_of
        || exception.removal_criteria.trim().len() < 10
    {
        return Err("exception is missing required, current approval evidence".to_owned());
    }
    if exception.approval.record == "pending"
        || exception.approval.record == "self"
        || (!exception.approval.record.starts_with("local-review:")
            && !valid_review_url(&exception.approval.record))
    {
        return Err("exception approval record is not a verifiable review reference".to_owned());
    }
    if !allow_fixture_review {
        return Err(
            "exception approval record needs independently validated review evidence; fixture review records are not accepted"
                .to_owned(),
        );
    }
    if exception.approval.record.starts_with("local-review:")
        && !valid_relative_path(
            exception
                .approval
                .record
                .strip_prefix("local-review:")
                .unwrap_or_default(),
        )
    {
        return Err("local exception review record must name a safe review artifact".to_owned());
    }
    for rule in &exception.rule_ids {
        if !valid_rule_id(rule) || !ordinary_style_rule(rule) {
            return Err(format!("invalid exception rule {rule}"));
        }
        if let Some(known) = known_rule_ids
            && !known.contains_key(rule)
        {
            return Err(format!("exception references unknown rule {rule}"));
        }
        if let Some(known) = known_rule_ids
            && !known[rule]
        {
            return Err(format!("rule {rule} is not exception eligible"));
        }
    }
    for path in &exception.paths {
        if !valid_relative_path(path) || path == "." || path.contains('*') {
            return Err(format!("exception path is not exact and relative: {path}"));
        }
    }
    Ok(())
}
