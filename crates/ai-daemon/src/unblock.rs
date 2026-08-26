//! Running blocking work from a D-Bus method without wedging the bus.
//!
//! zbus dispatches every incoming method call on one internal executor thread.
//! A handler that blocks there does not merely make the daemon slow: it stops
//! the connection reading its own socket, so a handler that blocks *on a D-Bus
//! call of its own* — asking polkit whether the caller may install a model, say
//! — is waiting for a reply that only the thread it is blocking could deliver.
//! That is a deadlock, and it takes the whole daemon with it.
//!
//! So anything slow gets handed to a thread and awaited. This is a hand-rolled
//! `unblock` rather than a dependency because it is thirty lines and the
//! alternative is pulling a thread-pool crate into a privileged process to do
//! what `std::thread::spawn` already does.

use std::future::Future;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

struct Shared<T> {
    /// `Err(())` means the work panicked. The panic is not resumed here: a
    /// backend or a fetch falling over should become an error on one D-Bus
    /// call, not the end of the daemon.
    result: Option<Result<T, ()>>,
    waker: Option<Waker>,
}

pub struct Unblock<T> {
    shared: Arc<Mutex<Shared<T>>>,
}

/// Run `work` on its own thread and yield until it finishes.
pub fn unblock<T, F>(work: F) -> Unblock<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let shared = Arc::new(Mutex::new(Shared { result: None, waker: None }));
    let handle = shared.clone();
    // If the thread cannot be spawned there is nothing sensible to do but
    // record the failure the same way a panic is recorded, so the awaiting
    // side still completes.
    if std::thread::Builder::new()
        .name("unblock".into())
        .spawn(move || {
            let outcome = catch_unwind(AssertUnwindSafe(work)).map_err(|_| ());
            let mut state = handle.lock().unwrap();
            state.result = Some(outcome);
            if let Some(waker) = state.waker.take() {
                waker.wake();
            }
        })
        .is_err()
    {
        shared.lock().unwrap().result = Some(Err(()));
    }
    Unblock { shared }
}

impl<T> Future for Unblock<T> {
    type Output = Result<T, ()>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let mut state = self.shared.lock().unwrap();
        match state.result.take() {
            Some(result) => Poll::Ready(result),
            None => {
                state.waker = Some(context.waker().clone());
                Poll::Pending
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal executor, so the test exercises the waker rather than a
    /// spin loop that would pass even if `poll` never registered one.
    fn block_on<F: Future>(mut future: F) -> F::Output {
        use std::sync::mpsc::{sync_channel, SyncSender};
        use std::task::{RawWaker, RawWakerVTable};

        struct Signal(SyncSender<()>);
        unsafe fn clone(data: *const ()) -> RawWaker {
            Arc::increment_strong_count(data as *const Signal);
            RawWaker::new(data, &VTABLE)
        }
        unsafe fn wake(data: *const ()) {
            let signal = Arc::from_raw(data as *const Signal);
            let _ = signal.0.try_send(());
        }
        unsafe fn wake_by_ref(data: *const ()) {
            let signal = &*(data as *const Signal);
            let _ = signal.0.try_send(());
        }
        unsafe fn drop_signal(data: *const ()) {
            drop(Arc::from_raw(data as *const Signal));
        }
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop_signal);

        let (sender, receiver) = sync_channel(1);
        let signal = Arc::new(Signal(sender));
        let raw = Arc::into_raw(signal);
        // SAFETY: the vtable's functions all treat the pointer as an
        // `Arc<Signal>` and balance their own reference counts.
        let waker = unsafe { Waker::from_raw(RawWaker::new(raw as *const (), &VTABLE)) };
        let mut context = Context::from_waker(&waker);
        let mut future = unsafe { Pin::new_unchecked(&mut future) };
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(value) => return value,
                Poll::Pending => {
                    let _ = receiver.recv();
                }
            }
        }
    }

    #[test]
    fn the_result_comes_back_and_the_waker_is_used() {
        let value = block_on(unblock(|| {
            std::thread::sleep(std::time::Duration::from_millis(50));
            41 + 1
        }));
        assert_eq!(value, Ok(42));
    }

    #[test]
    fn a_panic_becomes_an_error_rather_than_a_hang() {
        let value: Result<(), ()> = block_on(unblock(|| panic!("the backend fell over")));
        assert_eq!(value, Err(()), "the awaiting method must complete, not wait forever");
    }
}
