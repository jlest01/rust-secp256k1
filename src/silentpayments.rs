//! This module implements high-level Rust bindings for silent payments

use core::fmt;

#[cfg(feature = "std")]
use std;

use core;

use secp256k1_sys::secp256k1_silentpayments_sender_create_outputs;

use crate::ffi::{self, CPtr};
use crate::{Keypair, PublicKey, SecretKey, XOnlyPublicKey};
use crate::Secp256k1;
use crate::Verification;

fn copy_to_ffi_pubkey(pubkey: &PublicKey) -> ffi::PublicKey {

    unsafe {
        // Get a pointer to the inner ffi::PublicKey
        let ffi_pubkey_ptr: *const ffi::PublicKey = pubkey.as_c_ptr();
        
        // Dereference the pointer to get the ffi::PublicKey
        // Then create a copy of it
        (*ffi_pubkey_ptr).clone()
    }
}


/// Struct to store recipient data
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct SilentpaymentsRecipient(ffi::SilentpaymentsRecipient);

impl SilentpaymentsRecipient {

    /// Get a new SilentpaymentsRecipient
    pub fn new(scan_pubkey: &PublicKey,  spend_pubkey: &PublicKey, index: usize) -> Self {

        /* Self(ffi::SilentpaymentsRecipient {
            scan_pubkey: copy_to_ffi_pubkey(scan_pubkey),
            spend_pubkey: copy_to_ffi_pubkey(spend_pubkey),
            index,
        })   */

        Self(ffi::SilentpaymentsRecipient::new(
            &copy_to_ffi_pubkey(scan_pubkey),
            &copy_to_ffi_pubkey(spend_pubkey),
            index
        ))
    }

    /// Get a const pointer to the inner SilentpaymentsRecipient
    pub fn as_ptr(&self) -> *const ffi::SilentpaymentsRecipient {
        &self.0
    }

    /// Get a mut pointer to the inner SilentpaymentsRecipient
    pub fn as_mut_ptr(&mut self) -> *mut ffi::SilentpaymentsRecipient {
        &mut self.0
    }
}

impl CPtr for SilentpaymentsRecipient {
    type Target = ffi::SilentpaymentsRecipient;
    fn as_c_ptr(&self) -> *const Self::Target { &self.0 }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target { &mut self.0 }
}

/// Sender Output creation errors
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub enum SenderOutputCreationError {
    /// Unexpected failures
    Failure,
}

#[cfg(feature = "std")]
impl std::error::Error for SenderOutputCreationError {}

impl fmt::Display for SenderOutputCreationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            SenderOutputCreationError::Failure => write!(f, "Failed to create silent payments outputs"),
        }
    }
}

/// lorem ipsum
pub fn silentpayments_sender_create_outputs<C: Verification>(
    secp: &Secp256k1<C>,
    recipients: &[SilentpaymentsRecipient],
    smallest_outpoint: &[u8; 36],
    taproot_seckeys: Option<&[Keypair]>,
    plain_seckeys: Option<&[SecretKey]>,
) -> Result<Vec<XOnlyPublicKey>, &'static str> {
    let cx = secp.ctx().as_ptr();
    let n_tx_outputs = recipients.len();

    let ffi_recipients: Vec<ffi::SilentpaymentsRecipient> = recipients.iter().map(|r| r.0.clone()).collect();
    let ffi_recipients_ptrs: Vec<_> = ffi_recipients.iter().map(|r| r as *const _).collect();

    // Create vectors to hold the data, ensuring it stays in scope
    let mut ffi_taproot_seckeys = Vec::new();
    let mut ffi_taproot_seckeys_ptrs = Vec::new();
    let mut plain_seckeys_u8_array = Vec::new();
    let mut plain_seckeys_ptrs = Vec::new();

    // Populate taproot seckeys if provided
    if let Some(taproot_seckeys) = taproot_seckeys {
        ffi_taproot_seckeys = taproot_seckeys
            .iter()
            .map(|tap_keypair| unsafe { (*tap_keypair.as_c_ptr()).clone() })
            .collect();
        ffi_taproot_seckeys_ptrs = ffi_taproot_seckeys
            .iter()
            .map(|keypair| keypair as *const ffi::Keypair)
            .collect();
    }

    // Populate plain seckeys if provided
    if let Some(plain_seckeys) = plain_seckeys {
        plain_seckeys_u8_array = plain_seckeys
            .iter()
            .map(|k| k.secret_bytes())
            .collect();
        plain_seckeys_ptrs = plain_seckeys_u8_array
            .iter()
            .map(|k| k.as_ptr())
            .collect();
    }

    let n_taproot_seckeys = ffi_taproot_seckeys.len();
    let n_plain_seckeys = plain_seckeys_u8_array.len();

    let result = unsafe {
        let mut out_pubkeys = vec![ffi::XOnlyPublicKey::new(); n_tx_outputs];
        let mut out_pubkeys_ptrs: Vec<_> = out_pubkeys.iter_mut().map(|k| k as *mut _).collect();

        let res = secp256k1_silentpayments_sender_create_outputs(
            cx,
            out_pubkeys_ptrs.as_mut_ptr(),
            ffi_recipients_ptrs.as_ptr(),
            n_tx_outputs,
            smallest_outpoint.as_ptr(),
            if !ffi_taproot_seckeys_ptrs.is_empty() { ffi_taproot_seckeys_ptrs.as_ptr() } else { std::ptr::null() },
            n_taproot_seckeys,
            if !plain_seckeys_ptrs.is_empty() { plain_seckeys_ptrs.as_ptr() } else { std::ptr::null() },
            n_plain_seckeys,
        );

        if res == 1 {
            Ok(out_pubkeys.into_iter().map(XOnlyPublicKey::from).collect())
        } else {
            Err("silentpayments_test_outputs failed")
        }
    };

    result
}
