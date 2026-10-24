use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;

use peerbay_lib::app::{AppRuntime, InvalidTransition, LifecycleState};

#[test]
fn runtime_starts_and_stops_without_webview() {
    let runtime = AppRuntime::new();

    assert_eq!(
        runtime.lifecycle().expect("read lifecycle"),
        LifecycleState::Created
    );
    runtime.start().expect("runtime should start");
    assert_eq!(
        runtime.lifecycle().expect("read lifecycle"),
        LifecycleState::Ready
    );

    runtime.shutdown().expect("runtime should shut down");
    assert_eq!(
        runtime.lifecycle().expect("read lifecycle"),
        LifecycleState::Stopped
    );
}

#[test]
fn headless_runtime_accepts_backend_work_without_webview() {
    let runtime = AppRuntime::new();
    let worker_started = Arc::new(AtomicBool::new(false));
    let worker_started_in_worker = Arc::clone(&worker_started);

    runtime.start().expect("headless runtime should start");
    runtime
        .spawn_worker("headless-test-worker", move |context| {
            worker_started_in_worker.store(true, Ordering::Release);
            while !context.shutdown_requested() {
                thread::yield_now();
            }
        })
        .expect("headless runtime should accept backend work");

    runtime.shutdown().expect("runtime should shut down");

    assert!(worker_started.load(Ordering::Acquire));
    assert_eq!(
        runtime.lifecycle().expect("read lifecycle"),
        LifecycleState::Stopped
    );
    assert_eq!(runtime.active_worker_count().expect("read worker count"), 0);
}

#[test]
fn runtime_follows_explicit_startup_stages() {
    let runtime = AppRuntime::new();

    runtime
        .transition(LifecycleState::LoadingIdentity)
        .expect("identity stage should start");
    assert_eq!(
        runtime.lifecycle().expect("read lifecycle"),
        LifecycleState::LoadingIdentity
    );
    runtime
        .transition(LifecycleState::LoadingStore)
        .expect("store stage should start");
    runtime
        .transition(LifecycleState::StartingPlatform)
        .expect("platform stage should start");
    runtime
        .transition(LifecycleState::StartingDiscovery)
        .expect("discovery stage should start");
    runtime
        .transition(LifecycleState::Ready)
        .expect("ready stage should start");
    assert_eq!(
        runtime.lifecycle().expect("read lifecycle"),
        LifecycleState::Ready
    );
}

#[test]
fn runtime_rejects_skipping_startup_stages() {
    let runtime = AppRuntime::new();

    let error = runtime
        .transition(LifecycleState::Ready)
        .expect_err("runtime must not skip initialization stages");
    let error = error
        .downcast_inner::<InvalidTransition>()
        .expect("invalid transition should be preserved");
    assert_eq!(error.from, LifecycleState::Created);
    assert_eq!(error.to, LifecycleState::Ready);
}

#[test]
fn shutdown_requests_workers_and_joins_them() {
    let runtime = AppRuntime::new();
    runtime.start().expect("runtime should start");
    let worker_stopped = Arc::new(AtomicBool::new(false));
    let worker_stopped_in_worker = Arc::clone(&worker_stopped);

    runtime
        .spawn_worker("test-worker", move |context| {
            while !context.shutdown_requested() {
                thread::yield_now();
            }
            worker_stopped_in_worker.store(true, Ordering::Release);
        })
        .expect("worker should start");

    assert_eq!(runtime.active_worker_count().expect("read worker count"), 1);
    runtime.shutdown().expect("runtime should shut down");

    assert!(worker_stopped.load(Ordering::Acquire));
    assert_eq!(runtime.active_worker_count().expect("read worker count"), 0);
}
