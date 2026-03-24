use crate::error::{EnvzError, Result};

use core_foundation::base::{CFTypeRef, TCFType};
use core_foundation::data::{CFData, CFDataRef};
use core_foundation::dictionary::CFMutableDictionary;
use core_foundation::string::CFString;
use security_framework_sys::base::errSecSuccess;
use security_framework_sys::item::*;
use security_framework_sys::keychain_item::{SecItemAdd, SecItemCopyMatching, SecItemDelete};
use std::ffi::c_void;
use std::ptr;

const SERVICE: &str = "envz";

// OSStatus error codes
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
const ERR_SEC_AUTH_FAILED: i32 = -25293;
const ERR_SEC_USER_CANCELED: i32 = -128;

unsafe extern "C" {
    static kSecAttrAccess: CFTypeRef;
    fn SecTrustedApplicationCreateFromPath(
        path: *const u8,
        app: *mut CFTypeRef,
    ) -> i32;
    fn SecAccessCreate(
        descriptor: CFTypeRef,
        trusted_list: CFTypeRef,
        access_ref: *mut CFTypeRef,
    ) -> i32;
    fn CFArrayCreate(
        allocator: CFTypeRef,
        values: *const *const c_void,
        num_values: isize,
        callbacks: *const c_void,
    ) -> CFTypeRef;
    static kCFTypeArrayCallBacks: c_void;
}

/// Helper: add a key-value pair to a CF mutable dictionary using raw pointers.
unsafe fn dict_set(
    dict: &mut CFMutableDictionary<*const c_void, *const c_void>,
    key: *const c_void,
    value: *const c_void,
) {
    dict.add(&key, &value);
}

/// Create a SecAccess that allows any application to read the keychain item
/// without triggering a password prompt. This is safe because:
/// - The vault data is AES-256-GCM encrypted with the stored key
/// - Biometric vaults require Touch ID authentication before keychain access
/// - The login keychain is only unlocked while the user is logged in
fn create_permissive_access() -> Option<CFTypeRef> {
    unsafe {
        let mut trusted_app: CFTypeRef = ptr::null_mut();
        let status = SecTrustedApplicationCreateFromPath(ptr::null(), &mut trusted_app);
        if status != errSecSuccess {
            return None;
        }

        let values = [trusted_app as *const c_void];
        let trusted_list = CFArrayCreate(
            ptr::null_mut(),
            values.as_ptr(),
            1,
            &kCFTypeArrayCallBacks as *const _ as *const c_void,
        );

        let label = CFString::new("envz vault key");
        let mut access: CFTypeRef = ptr::null_mut();
        let status = SecAccessCreate(
            label.as_concrete_TypeRef() as CFTypeRef,
            trusted_list,
            &mut access,
        );

        core_foundation::base::CFRelease(trusted_list);
        core_foundation::base::CFRelease(trusted_app);

        if status == errSecSuccess {
            Some(access)
        } else {
            None
        }
    }
}

/// Store the master key in the macOS Keychain (file-based keychain, no entitlements required).
/// Biometric authentication is handled separately via the `biometric` module.
pub fn store_key(vault_id: &str, key: &[u8]) -> Result<()> {
    // Remove any stale entry first (ignore errors)
    let _ = delete_key(vault_id);

    let service = CFString::new(SERVICE);
    let account = CFString::new(vault_id);
    let key_data = CFData::from_buffer(key);

    unsafe {
        let mut dict = CFMutableDictionary::new();
        dict_set(&mut dict, kSecClass as *const c_void, kSecClassGenericPassword as *const c_void);
        dict_set(
            &mut dict,
            kSecAttrService as *const c_void,
            service.as_concrete_TypeRef() as *const c_void,
        );
        dict_set(
            &mut dict,
            kSecAttrAccount as *const c_void,
            account.as_concrete_TypeRef() as *const c_void,
        );
        dict_set(
            &mut dict,
            kSecValueData as *const c_void,
            key_data.as_concrete_TypeRef() as *const c_void,
        );

        // Allow any local application to access this item without a password prompt
        if let Some(access) = create_permissive_access() {
            dict_set(&mut dict, kSecAttrAccess as *const c_void, access);
            core_foundation::base::CFRelease(access);
        }

        let status = SecItemAdd(dict.as_concrete_TypeRef() as *const _, ptr::null_mut());
        if status != errSecSuccess {
            return Err(EnvzError::Keychain(format!(
                "Failed to store key in keychain (error {status})"
            )));
        }
    }
    Ok(())
}

/// Retrieve the master key from the macOS Keychain.
pub fn retrieve_key(vault_id: &str) -> Result<Vec<u8>> {
    let service = CFString::new(SERVICE);
    let account = CFString::new(vault_id);

    unsafe {
        let mut dict = CFMutableDictionary::new();
        dict_set(&mut dict, kSecClass as *const c_void, kSecClassGenericPassword as *const c_void);
        dict_set(
            &mut dict,
            kSecAttrService as *const c_void,
            service.as_concrete_TypeRef() as *const c_void,
        );
        dict_set(
            &mut dict,
            kSecAttrAccount as *const c_void,
            account.as_concrete_TypeRef() as *const c_void,
        );
        dict_set(
            &mut dict,
            kSecReturnData as *const c_void,
            core_foundation::boolean::kCFBooleanTrue as *const c_void,
        );

        let mut result: CFTypeRef = ptr::null_mut();
        let status = SecItemCopyMatching(dict.as_concrete_TypeRef() as *const _, &mut result);

        match status {
            s if s == errSecSuccess => {
                let data = CFData::wrap_under_create_rule(result as CFDataRef);
                Ok(data.to_vec())
            }
            s if s == ERR_SEC_ITEM_NOT_FOUND => Err(EnvzError::Keychain(
                "No keychain entry found. Vault may need to be re-initialized.".into(),
            )),
            s if s == ERR_SEC_AUTH_FAILED || s == ERR_SEC_USER_CANCELED => {
                Err(EnvzError::AuthFailed)
            }
            _ => Err(EnvzError::Keychain(format!(
                "Failed to retrieve key from keychain (error {status})"
            ))),
        }
    }
}

/// Delete the keychain entry for a vault.
pub fn delete_key(vault_id: &str) -> Result<()> {
    let service = CFString::new(SERVICE);
    let account = CFString::new(vault_id);

    unsafe {
        let mut dict = CFMutableDictionary::new();
        dict_set(&mut dict, kSecClass as *const c_void, kSecClassGenericPassword as *const c_void);
        dict_set(
            &mut dict,
            kSecAttrService as *const c_void,
            service.as_concrete_TypeRef() as *const c_void,
        );
        dict_set(
            &mut dict,
            kSecAttrAccount as *const c_void,
            account.as_concrete_TypeRef() as *const c_void,
        );

        let status = SecItemDelete(dict.as_concrete_TypeRef() as *const _);
        if status != errSecSuccess && status != ERR_SEC_ITEM_NOT_FOUND {
            return Err(EnvzError::Keychain(format!(
                "Failed to delete keychain entry (error {status})"
            )));
        }
    }
    Ok(())
}
