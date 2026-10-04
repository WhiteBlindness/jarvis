//! The JARVIS Core: the only component that decides and acts.
//!
//! A request from a worker goes through [`session`] (framing, decoding,
//! limits), [`policy`] (capability extraction and evaluation), [`approval`]
//! when a person must confirm, and [`gateway`] (timeouts, cancellation, result
//! verification); every step is recorded in the [`store`]. [`daemon`] runs the
//! long-lived Core: it supervises the worker ([`supervisor`]) and serves local
//! clients over [`rpc`].

pub mod approval;
pub mod config;
pub mod confinement;
pub mod daemon;
pub mod framing;
pub mod gateway;
pub mod hub;
pub mod policy;
pub mod rpc;
pub mod session;
pub mod store;
pub mod supervisor;
