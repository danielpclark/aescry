//! AES using the x86 AES-NI instructions.
//!
//! The AES instructions run in constant time, so this backend does not leak
//! the key or data through cache timing.  The key schedule's SubWord step is
//! also computed with `AESENCLAST`, so no table lookups depend on the key.

#![allow(unsafe_code)]

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use super::soft::expand_encryption_key;
use super::KeyRef;
use crate::algorithms::put_u32;

/// Whether this CPU supports the AES-NI instructions.
pub(crate) fn available() -> bool {
    std::is_x86_feature_detected!("aes") && std::is_x86_feature_detected!("sse2")
}

/// AES-NI round keys.
///
/// A value of this type can only be created by [`KeySchedule::new`], which
/// checks that the CPU supports AES-NI, so its methods may use the
/// instructions.
#[derive(Clone)]
pub(crate) struct KeySchedule {
    ek: [__m128i; 15],
    dk: [__m128i; 15],
    nr: usize,
}

impl KeySchedule {
    /// Expand a 16, 24 or 32 octet key, or return `None` if the CPU does not
    /// support AES-NI.
    pub(crate) fn new(key: KeyRef<'_>) -> Option<Self> {
        if !available() {
            return None;
        }

        // SAFETY: AES-NI and SSE2 support was checked above.
        Some(unsafe { Self::expand(key) })
    }

    #[target_feature(enable = "aes,sse2")]
    unsafe fn expand(key: KeyRef<'_>) -> Self {
        // Build the FIPS-197 schedule with a constant-time SubWord.
        let (mut words, nr) = expand_encryption_key(key, |w| sub_word(w));

        let zero = _mm_setzero_si128();
        let mut ks = KeySchedule { ek: [zero; 15], dk: [zero; 15], nr };

        for round in 0..=nr {
            let mut bytes = [0u8; 16];
            for j in 0..4 {
                put_u32(words[round * 4 + j], &mut bytes, j * 4);
            }
            ks.ek[round] = _mm_loadu_si128(bytes.as_ptr() as *const __m128i);
            crate::zeroize::Zeroize::zeroize(&mut bytes[..]);
        }

        // Equivalent inverse cipher: reversed keys, InvMixColumns applied to
        // all but the first and last.
        ks.dk[0] = ks.ek[nr];
        for round in 1..nr {
            ks.dk[round] = _mm_aesimc_si128(ks.ek[nr - round]);
        }
        ks.dk[nr] = ks.ek[0];

        crate::zeroize::Zeroize::zeroize(&mut words[..]);
        ks
    }

    pub(crate) fn encrypt(&self, block: &mut [u8; 16]) {
        // SAFETY: a KeySchedule only exists if AES-NI is available.
        unsafe { encrypt(self, block) }
    }

    pub(crate) fn decrypt(&self, block: &mut [u8; 16]) {
        // SAFETY: a KeySchedule only exists if AES-NI is available.
        unsafe { decrypt(self, block) }
    }

    pub(crate) fn rounds(&self) -> usize {
        self.nr
    }
}

impl Drop for KeySchedule {
    fn drop(&mut self) {
        for key in self.ek.iter_mut().chain(self.dk.iter_mut()) {
            // SAFETY: writing a zero vector through a valid, aligned reference.
            unsafe { core::ptr::write_volatile(key, _mm_setzero_si128()) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

/// SubWord(w) using AESENCLAST: with the word broadcast to every column,
/// ShiftRows has no effect, leaving SubBytes of each octet.
#[target_feature(enable = "aes,sse2")]
unsafe fn sub_word(w: u32) -> u32 {
    let state = _mm_set1_epi32(w as i32);
    _mm_cvtsi128_si32(_mm_aesenclast_si128(state, _mm_setzero_si128())) as u32
}

#[target_feature(enable = "aes,sse2")]
unsafe fn encrypt(ks: &KeySchedule, block: &mut [u8; 16]) {
    let mut state = _mm_loadu_si128(block.as_ptr() as *const __m128i);

    state = _mm_xor_si128(state, ks.ek[0]);
    for round in 1..ks.nr {
        state = _mm_aesenc_si128(state, ks.ek[round]);
    }
    state = _mm_aesenclast_si128(state, ks.ek[ks.nr]);

    _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, state);
}

#[target_feature(enable = "aes,sse2")]
unsafe fn decrypt(ks: &KeySchedule, block: &mut [u8; 16]) {
    let mut state = _mm_loadu_si128(block.as_ptr() as *const __m128i);

    state = _mm_xor_si128(state, ks.dk[0]);
    for round in 1..ks.nr {
        state = _mm_aesdec_si128(state, ks.dk[round]);
    }
    state = _mm_aesdeclast_si128(state, ks.dk[ks.nr]);

    _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, state);
}
