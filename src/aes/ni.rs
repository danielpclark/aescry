//! AES using the x86 AES-NI instructions.
//!
//! The AES instructions run in constant time, so this backend does not leak
//! the key or data through cache timing.  The key schedule's SubWord step is
//! also computed with `AESENCLAST`, so no table lookups depend on the key.
//!
//! # Soundness
//!
//! The only precondition of the `#[target_feature]` functions below is that
//! the CPU supports AES-NI and SSE2.  That is captured by [`AesNi`], a
//! zero-sized token that can only be created by [`AesNi::detect`] after
//! runtime detection.  Every function that uses the instructions requires a
//! token (directly, or through a [`KeySchedule`] that holds one), so the
//! precondition is checked by the type system rather than by comments.

// Kernel code: round-key arrays have 15 entries and are indexed by round
// numbers up to the validated key size's round count (at most 14).
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
#![allow(unsafe_code)]

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use super::soft::expand_encryption_key;
use super::KeyRef;
use crate::algorithms::put_u32;
use crate::zeroize::Zeroize;

/// Proof that this CPU supports AES-NI and SSE2.
///
/// The field is private and the only constructor is [`AesNi::detect`], so
/// holding an `AesNi` means detection succeeded.
#[derive(Clone, Copy, Debug)]
pub(crate) struct AesNi(());

impl AesNi {
    /// Detect AES-NI and SSE2 at runtime.
    ///
    /// Always `None` under Miri, which does not emulate these instructions.
    pub(crate) fn detect() -> Option<Self> {
        if cfg!(miri) {
            return None;
        }
        if std::is_x86_feature_detected!("aes") && std::is_x86_feature_detected!("sse2") {
            Some(AesNi(()))
        } else {
            None
        }
    }
}

/// Whether this CPU supports the AES-NI instructions.
pub(crate) fn available() -> bool {
    AesNi::detect().is_some()
}

/// AES-NI round keys, together with the proof that AES-NI is available.
#[derive(Clone)]
pub(crate) struct KeySchedule {
    token: AesNi,
    ek: [__m128i; 15],
    dk: [__m128i; 15],
    nr: usize,
}

impl KeySchedule {
    /// Expand a key, or return `None` if the CPU does not support AES-NI.
    pub(crate) fn new(key: KeyRef<'_>) -> Option<Self> {
        let token = AesNi::detect()?;
        // SAFETY: `token` proves AES-NI and SSE2 are available, the only
        // precondition of `expand`.
        Some(unsafe { expand(token, key) })
    }

    pub(crate) fn encrypt(&self, block: &mut [u8; 16]) {
        // SAFETY: `self.token` proves AES-NI and SSE2 are available.
        unsafe { encrypt(self.token, self, block) }
    }

    pub(crate) fn decrypt(&self, block: &mut [u8; 16]) {
        // SAFETY: `self.token` proves AES-NI and SSE2 are available.
        unsafe { decrypt(self.token, self, block) }
    }

    pub(crate) fn rounds(&self) -> usize {
        self.nr
    }
}

impl Drop for KeySchedule {
    fn drop(&mut self) {
        for key in self.ek.iter_mut().chain(self.dk.iter_mut()) {
            // SAFETY: `key` is a valid, aligned, exclusive reference to an
            // initialized `__m128i`; writing a plain value through it is
            // sound, and needs no CPU feature.
            unsafe { core::ptr::write_volatile(key, core::mem::zeroed()) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

// The intrinsics used below are `unsafe fn`s on the minimum supported Rust
// (1.63), but most are safe inside `#[target_feature]` functions on newer
// Rust, so each body is one `unsafe` block that may be unused on newer
// compilers.

/// Expand a key using a constant-time SubWord.
///
/// # Safety
///
/// The CPU must support AES-NI and SSE2 (guaranteed by the `AesNi` token).
#[target_feature(enable = "aes,sse2")]
#[allow(unused_unsafe)]
unsafe fn expand(token: AesNi, key: KeyRef<'_>) -> KeySchedule {
    // Build the FIPS-197 schedule with a constant-time SubWord.
    // SAFETY: `token` proves the features `sub_word` needs are available.
    let (mut words, nr) = expand_encryption_key(key, |w| unsafe { sub_word(token, w) });

    // SAFETY: AES-NI and SSE2 are available (see the function's safety
    // section); `_mm_loadu_si128` reads 16 octets from a 16-octet array and
    // allows unaligned pointers.
    let ks = unsafe {
        let zero = _mm_setzero_si128();
        let mut ks = KeySchedule { token, ek: [zero; 15], dk: [zero; 15], nr };

        for round in 0..=nr {
            let mut bytes = [0u8; 16];
            for j in 0..4 {
                put_u32(words[round * 4 + j], &mut bytes, j * 4);
            }
            ks.ek[round] = _mm_loadu_si128(bytes.as_ptr() as *const __m128i);
            bytes.zeroize();
        }

        // Equivalent inverse cipher: reversed keys, InvMixColumns applied to
        // all but the first and last.
        ks.dk[0] = ks.ek[nr];
        for round in 1..nr {
            ks.dk[round] = _mm_aesimc_si128(ks.ek[nr - round]);
        }
        ks.dk[nr] = ks.ek[0];
        ks
    };

    words.zeroize();
    ks
}

/// SubWord(w) using AESENCLAST: with the word broadcast to every column,
/// ShiftRows has no effect, leaving SubBytes of each octet.
///
/// # Safety
///
/// The CPU must support AES-NI and SSE2 (guaranteed by the token).
#[target_feature(enable = "aes,sse2")]
#[allow(unused_unsafe)]
unsafe fn sub_word(_token: AesNi, w: u32) -> u32 {
    // SAFETY: AES-NI and SSE2 are available (see the function's safety
    // section); these intrinsics only operate on register values.
    unsafe {
        let state = _mm_set1_epi32(w as i32);
        _mm_cvtsi128_si32(_mm_aesenclast_si128(state, _mm_setzero_si128())) as u32
    }
}

/// # Safety
///
/// The CPU must support AES-NI and SSE2 (guaranteed by the token).
#[target_feature(enable = "aes,sse2")]
#[allow(unused_unsafe)]
unsafe fn encrypt(_token: AesNi, ks: &KeySchedule, block: &mut [u8; 16]) {
    // SAFETY: AES-NI and SSE2 are available (see the function's safety
    // section); the unaligned load and store access exactly the 16 octets of
    // `block`.
    unsafe {
        let mut state = _mm_loadu_si128(block.as_ptr() as *const __m128i);

        state = _mm_xor_si128(state, ks.ek[0]);
        for round in 1..ks.nr {
            state = _mm_aesenc_si128(state, ks.ek[round]);
        }
        state = _mm_aesenclast_si128(state, ks.ek[ks.nr]);

        _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, state);
    }
}

/// # Safety
///
/// The CPU must support AES-NI and SSE2 (guaranteed by the token).
#[target_feature(enable = "aes,sse2")]
#[allow(unused_unsafe)]
unsafe fn decrypt(_token: AesNi, ks: &KeySchedule, block: &mut [u8; 16]) {
    // SAFETY: AES-NI and SSE2 are available (see the function's safety
    // section); the unaligned load and store access exactly the 16 octets of
    // `block`.
    unsafe {
        let mut state = _mm_loadu_si128(block.as_ptr() as *const __m128i);

        state = _mm_xor_si128(state, ks.dk[0]);
        for round in 1..ks.nr {
            state = _mm_aesdec_si128(state, ks.dk[round]);
        }
        state = _mm_aesdeclast_si128(state, ks.dk[ks.nr]);

        _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, state);
    }
}
