//! This module implements high-level Rust bindings for silent payments

use core::fmt;

#[cfg(feature = "std")]
use std;

use core;

use secp256k1_sys::secp256k1_silentpayments_test_outputs;

use crate::ffi::{self, CPtr};
use crate::{PublicKey, XOnlyPublicKey};
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
pub fn silentpayments_test_outputs<C: Verification>(
    secp: &Secp256k1<C>,
    recipients: &[SilentpaymentsRecipient],
    smallest_outpoint: &[u8; 36]
) -> Result<Vec<XOnlyPublicKey>, &'static str> {

    let cx = secp.ctx().as_ptr();

    

    let mut result_out_pubkeys = Vec::<XOnlyPublicKey>::new();

    

    let result = unsafe {

        // let mut generated_outputs = Vec::with_capacity(recipients.len());
    
        // for _ in 0..recipients.len() {
        //     let x_only_public_key = Box::new(ffi::XOnlyPublicKey::new());
        //     let ptr = Box::into_raw(x_only_public_key);
        //     generated_outputs.push(ptr);
        // }

        let n_tx_outputs: usize = recipients.len();

        let mut ffi_recipients = Vec::<ffi::SilentpaymentsRecipient>::new();
        let mut ffi_recipients_ptrs: Vec<*const ffi::SilentpaymentsRecipient> = vec![std::ptr::null(); n_tx_outputs];

        for recipient in recipients {
            let x = recipient.0;
            ffi_recipients.push(x.clone());
        }

        for i in 0..n_tx_outputs {
            ffi_recipients_ptrs[i] = &ffi_recipients[i] as *const ffi::SilentpaymentsRecipient;
        }

        let mut out_pubkeys: Vec<ffi::XOnlyPublicKey> = vec![ffi::XOnlyPublicKey::new(); n_tx_outputs];
        let mut out_pubkeys_ptrs: Vec<*mut ffi::XOnlyPublicKey> = vec![std::ptr::null_mut(); n_tx_outputs];

        for i in 0..n_tx_outputs {
            out_pubkeys_ptrs[i] = &mut out_pubkeys[i] as *mut ffi::XOnlyPublicKey;
        }

        let mut output36 = [0u8; 36];
        
        let x = secp256k1_silentpayments_test_outputs(
            cx,
            out_pubkeys_ptrs.as_mut_c_ptr(),
            ffi_recipients_ptrs.as_c_ptr(),
            recipients.len(),
            smallest_outpoint.as_c_ptr(),
            output36.as_mut_c_ptr()
        );

        println!("{}:", "output36");

        for i in output36.iter().cloned() {
            print!("{:02x}", i);
        }
        println!();

        if x == 1 {
            for out_pubkey in out_pubkeys {
                // let xonlypubkey = *Box::from_raw(i);
                // result_out_pubkeys.push(XOnlyPublicKey::from(xonlypubkey));
                let pubkey = XOnlyPublicKey::from(out_pubkey.to_owned());
                result_out_pubkeys.push(XOnlyPublicKey::from(pubkey.to_owned()));
                
                // for i in result.serialize().iter().cloned() {
                //     print!("{:02x}", i);
                // }
                // println!();
            }
        }

        x
    };

    if result == 1 {
        Ok(result_out_pubkeys)
    } else {
        Err("silentpayments_test_outputs failed")
    }
}