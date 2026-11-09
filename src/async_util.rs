//! Safe bounded/unbounded MPSC/MPMC channel primitives (`#![forbid(unsafe_code)]`).
//!
//! Replaces `gpui_kit::base::async_util` so the pure-Rust core library and tunnel actor
//! have zero dependency on custom GPU canvas frameworks.

#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex};

#[derive(Debug)]
struct ChannelInner<T> {
    queue: VecDeque<T>,
    senders: usize,
}

/// Cloneable multi-producer channel sender.
#[derive(Debug)]
pub struct Sender<T> {
    inner: Arc<(Mutex<ChannelInner<T>>, Condvar)>,
}

impl<T> Clone for Sender<T> {
    fn clone(&self) -> Self {
        let (lock, _) = &*self.inner;
        let mut guard = lock.lock().unwrap_or_else(|e| e.into_inner());
        guard.senders += 1;
        drop(guard);
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        let (lock, cv) = &*self.inner;
        let mut guard = lock.lock().unwrap_or_else(|e| e.into_inner());
        guard.senders = guard.senders.saturating_sub(1);
        if guard.senders == 0 {
            cv.notify_all();
        }
    }
}

impl<T> Sender<T> {
    /// Appends `item` to the channel queue and wakes one waiting receiver.
    pub fn try_send(&self, item: T) -> Result<(), T> {
        let (lock, cv) = &*self.inner;
        let mut guard = lock.lock().unwrap_or_else(|e| e.into_inner());
        guard.queue.push_back(item);
        cv.notify_one();
        Ok(())
    }
}

/// Error returned when a channel receive operation cannot produce an item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecvError;

/// Cloneable multi-consumer channel receiver.
#[derive(Clone, Debug)]
pub struct Receiver<T> {
    inner: Arc<(Mutex<ChannelInner<T>>, Condvar)>,
}

impl<T> Receiver<T> {
    /// Pops the next queued item immediately if available.
    pub fn try_recv(&self) -> Result<T, RecvError> {
        let (lock, _) = &*self.inner;
        let mut guard = lock.lock().unwrap_or_else(|e| e.into_inner());
        guard.queue.pop_front().ok_or(RecvError)
    }

    /// Blocks the current thread until an item arrives or all [`Sender`]s are dropped.
    pub fn recv_blocking(&self) -> Result<T, RecvError> {
        let (lock, cv) = &*self.inner;
        let mut guard = lock.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if let Some(item) = guard.queue.pop_front() {
                return Ok(item);
            }
            if guard.senders == 0 {
                return Err(RecvError);
            }
            guard = cv.wait(guard).unwrap_or_else(|e| e.into_inner());
        }
    }
}

/// Creates an unbounded multi-producer, multi-consumer channel pair.
#[must_use]
pub fn unbounded<T>() -> (Sender<T>, Receiver<T>) {
    let inner = Arc::new((
        Mutex::new(ChannelInner {
            queue: VecDeque::new(),
            senders: 1,
        }),
        Condvar::new(),
    ));
    (
        Sender {
            inner: Arc::clone(&inner),
        },
        Receiver { inner },
    )
}
