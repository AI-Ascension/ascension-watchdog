//! Queued-job protocol tests. Kept in a `#[path]` child file so the discovered
//! module path stays `native::queued_job_tests` and every test name is
//! unchanged.

use super::*;

fn binding(unit: &str, id: u32) -> ledger::JobBinding {
    ledger::JobBinding::from_object_path(unit, &format!("/org/freedesktop/systemd1/job/{id}"))
        .expect("valid queued job binding")
}

struct NoQueuedJobBackend;

impl QueuedJobBackend for NoQueuedJobBackend {}

#[test]
fn default_queued_job_methods_fail_closed() {
    let mut backend = NoQueuedJobBackend;
    let job = binding("synthetic.service", 7);
    let deadline = Instant::now() + Duration::from_secs(1);
    assert!(backend.queued_job_binding(job.unit()).is_none());
    assert!(matches!(
        backend.take_queued_job_binding(job.unit(), deadline),
        Err(BrokerError::Unavailable(_))
    ));
    assert!(matches!(
        backend.resolve_queued_job(&job, deadline),
        Err(BrokerError::Unavailable(_))
    ));
    assert!(matches!(
        backend.cancel_queued_job(&job, deadline),
        Err(BrokerError::Unavailable(_))
    ));
    let event =
        JobRemovedEvent::new(job.clone(), "done").expect("valid matching job removal event");
    assert_eq!(
        backend
            .observe_job_removed(&job, event, deadline)
            .expect("matching event"),
        JobRemovalOutcome::Done
    );
}

#[test]
fn native_queued_job_resolution_and_cancellation_honor_deadline() {
    let job = binding("synthetic.service", 8);
    let expired = Instant::now();
    assert!(matches!(
        NativeSystemdBackend::resolve_queued_job_native(&job, expired),
        Err(BrokerError::Unavailable(_))
    ));
    assert!(matches!(
        NativeSystemdBackend::cancel_queued_job_native(&job, expired),
        Err(BrokerError::Unavailable(_))
    ));
}

#[test]
fn retained_job_identity_rejects_replacement_and_late_removal() {
    let mut backend = NativeSystemdBackend::connect();
    let first = binding("synthetic.service", 11);
    let replacement = binding("synthetic.service", 12);
    backend
        .remember_queued_job(first.clone())
        .expect("first queued job");
    assert_eq!(backend.queued_job_binding(first.unit()), Some(&first));
    backend
        .remember_queued_job(first.clone())
        .expect("idempotent duplicate retention");
    assert!(matches!(
        backend.remember_queued_job(replacement.clone()),
        Err(BrokerError::Conflict(_))
    ));

    let late = JobRemovedEvent::new(replacement, "done").expect("valid but unrelated late event");
    assert!(matches!(
        backend.observe_job_removed(&first, late, Instant::now() + Duration::from_secs(1)),
        Err(BrokerError::Conflict(_))
    ));
    assert_eq!(backend.queued_job_binding(first.unit()), Some(&first));

    let removed =
        JobRemovedEvent::new(first.clone(), "canceled").expect("valid matching removal event");
    assert_eq!(
        backend
            .observe_job_removed(&first, removed, Instant::now() + Duration::from_secs(1))
            .expect("matching removal"),
        JobRemovalOutcome::Canceled
    );
    assert!(backend.queued_job_binding(first.unit()).is_none());
    assert!(matches!(
        backend.take_queued_job_binding(first.unit(), Instant::now() + Duration::from_secs(1)),
        Err(BrokerError::Conflict(_))
    ));
}

#[derive(Default)]
struct FakeCancellationBackend {
    binding: Option<ledger::JobBinding>,
    cancel_calls: usize,
}

impl QueuedJobBackend for FakeCancellationBackend {
    fn queued_job_binding(&self, unit: &str) -> Option<&ledger::JobBinding> {
        self.binding
            .as_ref()
            .filter(|binding| binding.unit() == unit)
    }

    fn resolve_queued_job(
        &mut self,
        binding: &ledger::JobBinding,
        deadline: Instant,
    ) -> BrokerResult<QueuedJobResolution> {
        remaining(deadline)?;
        match self.binding.as_ref() {
            Some(retained) if retained == binding => Ok(QueuedJobResolution::Queued),
            Some(_) => Err(BrokerError::Conflict(
                "fake queued job binding differs from the retained job".to_owned(),
            )),
            None => Ok(QueuedJobResolution::Gone),
        }
    }

    fn cancel_queued_job(
        &mut self,
        binding: &ledger::JobBinding,
        deadline: Instant,
    ) -> BrokerResult<QueuedJobCancellation> {
        match self.resolve_queued_job(binding, deadline)? {
            QueuedJobResolution::Gone => Ok(QueuedJobCancellation::AlreadyGone),
            QueuedJobResolution::Queued => {
                self.cancel_calls += 1;
                self.binding = None;
                Ok(QueuedJobCancellation::Submitted)
            }
        }
    }
}

#[test]
fn fake_concurrent_stop_attempts_cancel_only_the_exact_job_once() {
    let job = binding("synthetic.service", 13);
    let mut backend = FakeCancellationBackend {
        binding: Some(job.clone()),
        ..FakeCancellationBackend::default()
    };
    let deadline = Instant::now() + Duration::from_secs(1);
    assert_eq!(
        backend.cancel_queued_job(&job, deadline),
        Ok(QueuedJobCancellation::Submitted)
    );
    assert_eq!(
        backend.cancel_queued_job(&job, deadline),
        Ok(QueuedJobCancellation::AlreadyGone)
    );
    assert_eq!(backend.cancel_calls, 1);
}

#[test]
fn job_removed_decoder_requires_exact_manager_signal_and_identity()
-> Result<(), Box<dyn std::error::Error>> {
    let unit = "synthetic.service";
    let id = 14;
    let path: zbus::zvariant::OwnedObjectPath =
        format!("/org/freedesktop/systemd1/job/{id}").try_into()?;
    let message = zbus::Message::signal(
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
        "JobRemoved",
    )?
    .build(&(id, path.clone(), unit.to_owned(), "done".to_owned()))?;
    let event = decode_job_removed(&message)?;
    assert_eq!(event.binding(), &binding(unit, id));
    assert_eq!(event.result(), "done");
    assert_eq!(event.outcome(), JobRemovalOutcome::Done);

    let wrong_id = zbus::Message::signal(
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
        "JobRemoved",
    )?
    .build(&(id + 1, path, unit.to_owned(), "canceled".to_owned()))?;
    assert!(matches!(
        decode_job_removed(&wrong_id),
        Err(BrokerError::Conflict(_))
    ));

    let wrong_header = zbus::Message::signal(
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
        "UnitRemoved",
    )?
    .build(&(id, binding(unit, id).job_path(), unit.to_owned()))?;
    assert!(matches!(
        decode_job_removed(&wrong_header),
        Err(BrokerError::Invalid(_))
    ));
    assert!(JobRemovedEvent::new(binding(unit, id), "DONE").is_err());
    assert!(JobRemovedEvent::new(binding(unit, id), "").is_err());
    Ok(())
}
