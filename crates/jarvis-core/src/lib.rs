//! The JARVIS Core: the only component that decides and acts.
//!
//! A request from a worker goes through [`session`] (framing, decoding,
//! limits), [`policy`] (capability extraction and evaluation) and
//! [`gateway`] (timeouts, cancellation, result verification), and every step
//! is recorded in the [`store`]. [`runtime`] ties these together with the
//! worker process managed by [`supervisor`].

pub mod config;
pub mod framing;
pub mod gateway;
pub mod policy;
pub mod runtime;
pub mod session;
pub mod store;
pub mod supervisor;
