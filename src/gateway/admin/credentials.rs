use std::fmt;
use std::fs;
use std::path::Path;

use crate::gateway::admin::plan::AdminError;

/// Securely zeroes a byte slice in memory using volatile writes
/// to prevent compiler dead-store elimination.
pub fn zero_slice(slice: &mut [u8]) {
    for byte in slice.iter_mut() {
        unsafe {
            std::ptr::write_volatile(byte, 0);
        }
    }
}

/// A security-hardened byte buffer that zeroes its memory on Drop
/// and redacts itself in Debug and Display formatting.
#[derive(Clone, Eq)]
pub struct ProtectedBuffer {
    inner: Vec<u8>,
}

impl ProtectedBuffer {
    pub fn new(data: impl Into<Vec<u8>>) -> Self {
        Self { inner: data.into() }
    }

    pub fn push(&mut self, byte: u8) {
        self.inner.push(byte);
    }

    pub fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.inner.extend_from_slice(bytes);
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.inner
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn clear(&mut self) {
        zero_slice(&mut self.inner);
        self.inner.clear();
    }
}

impl Drop for ProtectedBuffer {
    fn drop(&mut self) {
        zero_slice(&mut self.inner);
    }
}

impl std::ops::Deref for ProtectedBuffer {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl std::ops::DerefMut for ProtectedBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl AsRef<[u8]> for ProtectedBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

impl fmt::Debug for ProtectedBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED_BUFFER (len={})]", self.inner.len())
    }
}

impl fmt::Display for ProtectedBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl PartialEq for ProtectedBuffer {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl PartialEq<[u8]> for ProtectedBuffer {
    fn eq(&self, other: &[u8]) -> bool {
        self.inner.as_slice() == other
    }
}

impl PartialEq<&[u8]> for ProtectedBuffer {
    fn eq(&self, other: &&[u8]) -> bool {
        self.inner.as_slice() == *other
    }
}

impl PartialEq<Vec<u8>> for ProtectedBuffer {
    fn eq(&self, other: &Vec<u8>) -> bool {
        &self.inner == other
    }
}

/// A security-hardened string wrapper that zeroes its allocated memory on Drop
/// and prevents accidental leak via Debug or Display formatting.
#[derive(Clone, PartialEq, Eq)]
pub struct ProtectedString {
    inner: Vec<u8>,
}

impl ProtectedString {
    pub fn new(s: impl AsRef<str>) -> Self {
        Self {
            inner: s.as_ref().as_bytes().to_vec(),
        }
    }

    /// Exposes the protected plaintext for authenticated transmission over an authorized session
    pub fn expose(&self) -> &str {
        std::str::from_utf8(&self.inner).unwrap_or("<invalid-utf8>")
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn clear(&mut self) {
        zero_slice(&mut self.inner);
        self.inner.clear();
    }
}

impl Drop for ProtectedString {
    fn drop(&mut self) {
        zero_slice(&mut self.inner);
    }
}

impl fmt::Debug for ProtectedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl fmt::Display for ProtectedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

/// Authenticated credentials for router management sessions.
/// Secret material is protected and never written to plaintext logs or files.
#[derive(Clone, PartialEq, Eq)]
pub struct RouterCredentials {
    pub username: String,
    pub password: ProtectedString,
}

impl RouterCredentials {
    pub fn new(username: impl Into<String>, password: impl AsRef<str>) -> Self {
        Self {
            username: username.into(),
            password: ProtectedString::new(password),
        }
    }
}

impl fmt::Debug for RouterCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RouterCredentials")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

#[cfg(windows)]
pub fn dpapi_encrypt(plaintext: &[u8]) -> Result<Vec<u8>, AdminError> {
    use std::ptr;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    let in_blob = CRYPT_INTEGER_BLOB {
        cbData: plaintext.len() as u32,
        pbData: plaintext.as_ptr() as *mut u8,
    };
    let mut out_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };

    let success = unsafe {
        CryptProtectData(
            &in_blob,
            ptr::null(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        )
    };

    if success == 0 {
        return Err(AdminError::CommunicationError(
            "Windows DPAPI encryption failed".into(),
        ));
    }

    let encrypted =
        unsafe { std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec() };

    unsafe {
        LocalFree(out_blob.pbData as _);
    }

    Ok(encrypted)
}

#[cfg(not(windows))]
pub fn dpapi_encrypt(plaintext: &[u8]) -> Result<Vec<u8>, AdminError> {
    // Fallback for non-Windows mock compilation: XOR-masked obfuscation
    let masked: Vec<u8> = plaintext.iter().map(|b| b ^ 0x5A).collect();
    Ok(masked)
}

#[cfg(windows)]
pub fn dpapi_decrypt(ciphertext: &[u8]) -> Result<ProtectedBuffer, AdminError> {
    use std::ptr;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    let in_blob = CRYPT_INTEGER_BLOB {
        cbData: ciphertext.len() as u32,
        pbData: ciphertext.as_ptr() as *mut u8,
    };
    let mut out_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };

    let success = unsafe {
        CryptUnprotectData(
            &in_blob,
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        )
    };

    if success == 0 {
        return Err(AdminError::AuthenticationFailed(
            "Failed to decrypt protected router credentials via Windows DPAPI".into(),
        ));
    }

    let slice = unsafe { std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize) };
    let decrypted = ProtectedBuffer::new(slice.to_vec());

    // Volatile zero DPAPI memory before freeing back to Windows LocalAlloc heap
    unsafe {
        for i in 0..(out_blob.cbData as usize) {
            std::ptr::write_volatile(out_blob.pbData.add(i), 0);
        }
        LocalFree(out_blob.pbData as _);
    }

    Ok(decrypted)
}

#[cfg(not(windows))]
pub fn dpapi_decrypt(ciphertext: &[u8]) -> Result<ProtectedBuffer, AdminError> {
    let unmasked: Vec<u8> = ciphertext.iter().map(|b| b ^ 0x5A).collect();
    Ok(ProtectedBuffer::new(unmasked))
}

/// Persists router credentials protected at rest using Windows DPAPI.
/// The encrypted file can only be decrypted by the current user account on this machine.
pub fn save_protected_credentials(
    path: &Path,
    creds: &RouterCredentials,
) -> Result<(), AdminError> {
    let mut raw = ProtectedBuffer::new(Vec::with_capacity(
        creds.username.len() + 1 + creds.password.len(),
    ));
    raw.extend_from_slice(creds.username.as_bytes());
    raw.push(b':');
    raw.extend_from_slice(creds.password.as_bytes());

    let encrypted = dpapi_encrypt(&raw)?;
    drop(raw);

    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    fs::write(path, encrypted).map_err(|e| {
        AdminError::CommunicationError(format!("Failed to write protected credential store: {}", e))
    })?;

    Ok(())
}

/// Loads and decrypts router credentials from protected DPAPI storage.
pub fn load_protected_credentials(path: &Path) -> Result<RouterCredentials, AdminError> {
    if !path.exists() {
        return Err(AdminError::AuthenticationFailed(format!(
            "No protected credentials found at {}",
            path.display()
        )));
    }

    let encrypted = fs::read(path).map_err(|e| {
        AdminError::CommunicationError(format!("Failed to read protected credential store: {}", e))
    })?;

    let decrypted = dpapi_decrypt(&encrypted)?;
    let colon_pos = decrypted.iter().position(|&b| b == b':');
    let pos = match colon_pos {
        Some(p) => p,
        None => {
            return Err(AdminError::AuthenticationFailed(
                "Malformed protected credential structure".into(),
            ));
        }
    };

    let user_str = std::str::from_utf8(&decrypted[..pos]).map_err(|_| {
        AdminError::AuthenticationFailed("Decrypted credentials contain invalid UTF-8".into())
    })?;
    let pass_str = std::str::from_utf8(&decrypted[(pos + 1)..]).map_err(|_| {
        AdminError::AuthenticationFailed("Decrypted credentials contain invalid UTF-8".into())
    })?;

    Ok(RouterCredentials::new(user_str, pass_str))
}
