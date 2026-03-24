use crate::error::{EnvzError, Result};
use core_foundation::base::{CFTypeRef, TCFType};
use core_foundation::dictionary::CFDictionaryRef;
use core_foundation::string::{CFString, CFStringRef};
use security_framework_sys::base::errSecSuccess;
use sha2::{Digest, Sha256};
use std::ffi::c_void;
use std::ptr;

// SecCode / SecStaticCode API
unsafe extern "C" {
    fn SecCodeCopySelf(flags: u32, self_ref: *mut CFTypeRef) -> i32;
    fn SecCodeCopyStaticCode(code: CFTypeRef, flags: u32, static_code: *mut CFTypeRef) -> i32;
    fn SecCodeCopySigningInformation(
        code: CFTypeRef,
        flags: u32,
        information: *mut CFDictionaryRef,
    ) -> i32;
    static kSecCodeInfoIdentifier: CFTypeRef;
    static kSecCodeInfoTeamIdentifier: CFTypeRef;
    fn CFDictionaryGetValue(dict: CFDictionaryRef, key: *const c_void) -> *const c_void;
}

const K_SEC_CS_SIGNING_INFORMATION: u32 = 1 << 1;

/// Extract a CFString value from the signing info dictionary.
unsafe fn get_string_from_dict(dict: CFDictionaryRef, key: CFTypeRef) -> Option<String> {
    unsafe {
        let val = CFDictionaryGetValue(dict, key);
        if val.is_null() {
            return None;
        }
        let cf_str = CFString::wrap_under_get_rule(val as CFStringRef);
        Some(cf_str.to_string())
    }
}

/// Retrieve a stable signing identity hash from the running binary.
///
/// Uses the **team identifier** (e.g. "AB1234CD5E") and **signing identifier**
/// (e.g. "net.gnarlylabs.envz") from the code signature. These are stable across
/// rebuilds as long as you sign with the same Developer ID certificate.
///
/// Returns SHA-256(team_id || ":" || signing_id) for use as HKDF info material.
pub fn signing_identity_hash() -> Result<[u8; 32]> {
    unsafe {
        // Get a reference to the running code
        let mut code_ref: CFTypeRef = ptr::null_mut();
        let status = SecCodeCopySelf(0, &mut code_ref);
        if status != errSecSuccess {
            return Err(EnvzError::Crypto(format!(
                "SecCodeCopySelf failed (error {status})"
            )));
        }

        // Get the static code (on-disk representation)
        let mut static_code: CFTypeRef = ptr::null_mut();
        let status = SecCodeCopyStaticCode(code_ref, 0, &mut static_code);
        core_foundation::base::CFRelease(code_ref);
        if status != errSecSuccess {
            return Err(EnvzError::Crypto(format!(
                "SecCodeCopyStaticCode failed (error {status})"
            )));
        }

        // Get signing information
        let mut info_dict: CFDictionaryRef = ptr::null_mut();
        let status = SecCodeCopySigningInformation(
            static_code,
            K_SEC_CS_SIGNING_INFORMATION,
            &mut info_dict,
        );
        core_foundation::base::CFRelease(static_code);
        if status != errSecSuccess {
            return Err(EnvzError::Crypto(format!(
                "SecCodeCopySigningInformation failed (error {status})"
            )));
        }

        // Extract team identifier (stable across rebuilds with same cert)
        let team_id = get_string_from_dict(info_dict, kSecCodeInfoTeamIdentifier);
        // Extract signing identifier (e.g. "net.gnarlylabs.envz", set at codesign time)
        let signing_id = get_string_from_dict(info_dict, kSecCodeInfoIdentifier);

        core_foundation::base::CFRelease(info_dict as CFTypeRef);

        let team_id = team_id.ok_or_else(|| {
            EnvzError::Crypto(
                "Binary is not signed with a Developer ID (no team identifier). \
                 Sign with: codesign -s \"Developer ID Application: ...\" --identifier net.gnarlylabs.envz <binary>"
                    .into(),
            )
        })?;

        let signing_id = signing_id
            .ok_or_else(|| EnvzError::Crypto("Binary has no signing identifier".into()))?;

        // Hash team_id:signing_id → stable 32-byte value for HKDF info
        let mut hasher = Sha256::new();
        hasher.update(team_id.as_bytes());
        hasher.update(b":");
        hasher.update(signing_id.as_bytes());
        Ok(hasher.finalize().into())
    }
}
