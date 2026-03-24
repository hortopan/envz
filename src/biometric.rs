use crate::error::{EnvzError, Result};
use core_foundation::base::TCFType;
use core_foundation::string::CFString;
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};

#[link(name = "LocalAuthentication", kind = "framework")]
unsafe extern "C" {}

#[link(name = "objc", kind = "dylib")]
unsafe extern "C" {
    fn objc_getClass(name: *const u8) -> *mut c_void;
    fn sel_registerName(name: *const u8) -> *mut c_void;
    fn objc_msgSend();
}

unsafe extern "C" {
    fn dispatch_semaphore_create(value: isize) -> *mut c_void;
    fn dispatch_semaphore_signal(dsema: *mut c_void) -> isize;
    fn dispatch_semaphore_wait(dsema: *mut c_void, timeout: u64) -> isize;
    fn dispatch_release(object: *mut c_void);
    static _NSConcreteStackBlock: [*const c_void; 32];
}

const DISPATCH_TIME_FOREVER: u64 = !0;
const LA_POLICY_BIOMETRICS: i64 = 1; // LAPolicyDeviceOwnerAuthenticationWithBiometrics

/// Check if Touch ID is available on this system.
pub fn is_available() -> bool {
    unsafe {
        let class = objc_getClass(b"LAContext\0".as_ptr());
        if class.is_null() {
            return false;
        }

        let sel_alloc = sel_registerName(b"alloc\0".as_ptr());
        let sel_init = sel_registerName(b"init\0".as_ptr());
        let sel_can = sel_registerName(b"canEvaluatePolicy:error:\0".as_ptr());
        let sel_release = sel_registerName(b"release\0".as_ptr());

        let alloc: extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void =
            std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
        let init: extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void =
            std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
        let can_evaluate: extern "C" fn(*mut c_void, *mut c_void, i64, *mut *mut c_void) -> bool =
            std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
        let release: extern "C" fn(*mut c_void, *mut c_void) =
            std::mem::transmute(objc_msgSend as unsafe extern "C" fn());

        let obj = alloc(class, sel_alloc);
        let obj = init(obj, sel_init);

        let mut error: *mut c_void = std::ptr::null_mut();
        let result = can_evaluate(obj, sel_can, LA_POLICY_BIOMETRICS, &mut error);
        release(obj, sel_release);
        result
    }
}

/// Authenticate with Touch ID. Blocks until the user responds.
pub fn authenticate(reason: &str) -> Result<()> {
    unsafe {
        let class = objc_getClass(b"LAContext\0".as_ptr());
        if class.is_null() {
            return Err(EnvzError::Keychain(
                "LocalAuthentication framework not available".into(),
            ));
        }

        let sel_alloc = sel_registerName(b"alloc\0".as_ptr());
        let sel_init = sel_registerName(b"init\0".as_ptr());
        let sel_evaluate =
            sel_registerName(b"evaluatePolicy:localizedReason:reply:\0".as_ptr());
        let sel_release = sel_registerName(b"release\0".as_ptr());

        let alloc: extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void =
            std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
        let init: extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void =
            std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
        let evaluate: extern "C" fn(*mut c_void, *mut c_void, i64, *mut c_void, *mut c_void) =
            std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
        let release: extern "C" fn(*mut c_void, *mut c_void) =
            std::mem::transmute(objc_msgSend as unsafe extern "C" fn());

        let obj = alloc(class, sel_alloc);
        let obj = init(obj, sel_init);

        let semaphore = dispatch_semaphore_create(0);
        let success = AtomicBool::new(false);

        // Objective-C block layout for the reply callback
        #[repr(C)]
        struct ReplyBlock {
            isa: *const c_void,
            flags: i32,
            reserved: i32,
            invoke: unsafe extern "C" fn(*mut ReplyBlock, bool, *mut c_void),
            descriptor: *const BlockDescriptor,
            success: *const AtomicBool,
            semaphore: *mut c_void,
        }

        #[repr(C)]
        struct BlockDescriptor {
            reserved: u64,
            size: u64,
        }

        static DESCRIPTOR: BlockDescriptor = BlockDescriptor {
            reserved: 0,
            size: std::mem::size_of::<ReplyBlock>() as u64,
        };

        unsafe extern "C" fn invoke(block: *mut ReplyBlock, success: bool, _error: *mut c_void) {
            unsafe {
                if let Some(flag) = (*block).success.as_ref() {
                    flag.store(success, Ordering::SeqCst);
                }
                dispatch_semaphore_signal((*block).semaphore);
            }
        }

        let mut block = ReplyBlock {
            isa: _NSConcreteStackBlock.as_ptr() as *const c_void,
            flags: 0,
            reserved: 0,
            invoke,
            descriptor: &DESCRIPTOR,
            success: &success,
            semaphore,
        };

        let reason_str = CFString::new(reason);

        evaluate(
            obj,
            sel_evaluate,
            LA_POLICY_BIOMETRICS,
            reason_str.as_concrete_TypeRef() as *mut c_void,
            &mut block as *mut ReplyBlock as *mut c_void,
        );

        dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
        dispatch_release(semaphore);
        release(obj, sel_release);

        if success.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(EnvzError::AuthFailed)
        }
    }
}
