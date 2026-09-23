//! Executable integrity and bounded SHA-256 hashing.
//!
//! Owns the retained immutable-image guards (`IntegrityGuards`), the kernel
//! file identity captured from the same handle that is hashed
//! (`FileIdentity`), the no-write/no-delete reopen path used by the launch
//! barrier, the bounded immutable-file hash (`hash_immutable_file`, `Sha256`)
//! and the image-identity deadline check shared by the identity capture
//! boundaries.
//!
//! Extracted verbatim from `native.rs`; immutable handle identity, the hash
//! size bound, the SHA-256 reference vectors, error semantics and visibility
//! are unchanged.  Items still used by sibling native modules are re-exported
//! from `native` under their original names.

use super::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_BACKUP_SEMANTICS, FILE_LIST_DIRECTORY,
    FILE_READ_ATTRIBUTES, FILE_SHARE_READ, GENERIC_READ, GetFileInformationByHandle, GetFileSizeEx,
    Instant, OPEN_EXISTING, OwnedHandle, Path, PathBuf, PlatformError, ReadFile, last_error, null,
    null_mut, wide_path,
};

const MAX_HASH_BYTES: u64 = 256 * 1024 * 1024;
const HASH_READ_BYTES: usize = 64 * 1024;

const SHA256_K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// Check a caller-owned absolute deadline at each native identity boundary.
/// Win32 calls below are synchronous, so this guard cannot interrupt an
/// individual kernel operation; it prevents additional work once the caller's
/// deadline has elapsed and records the timeout as a typed platform error.
pub(crate) fn check_image_deadline(deadline: Option<Instant>) -> Result<(), PlatformError> {
    if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
        return Err(PlatformError::Timeout(
            "Windows image identity deadline elapsed".to_owned(),
        ));
    }
    Ok(())
}

/// Handles held for the complete owner lifetime so the approved executable
/// file object and its release directory cannot be replaced underneath a
/// running process.  The directory handle protects the directory object from
/// removal or rename; it does not hash or pin dependent DLL contents.
#[derive(Debug)]
pub(crate) struct IntegrityGuards {
    // These handles are retained for their no-share lifetime; the fields are
    // intentionally not otherwise read after the initial hash.
    #[allow(dead_code)]
    executable: OwnedHandle,
    #[allow(dead_code)]
    release_directory: OwnedHandle,
    path: PathBuf,
    digest: String,
    pub(crate) file_identity: FileIdentity,
}

/// Kernel file identity captured from the same handle that is hashed.  A
/// canonical path is only a lookup; this tuple proves that the path still
/// resolves to the protected file object before a suspended child is resumed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FileIdentity {
    volume_serial: u32,
    file_index: u64,
    size: u64,
}

impl IntegrityGuards {
    /// Open and hash an immutable image while honoring the surrounding
    /// identity-capture deadline before and after the synchronous operation.
    pub(crate) fn open_until(
        path: &Path,
        deadline: Option<Instant>,
    ) -> Result<Self, PlatformError> {
        check_image_deadline(deadline)?;
        let guard = Self::open(path)?;
        check_image_deadline(deadline)?;
        Ok(guard)
    }

    pub(crate) fn open(path: &Path) -> Result<Self, PlatformError> {
        let parent = path.parent().ok_or_else(|| {
            PlatformError::Invalid("approved executable has no release directory".to_owned())
        })?;
        let release_directory = open_immutable_path(
            parent,
            FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
            FILE_FLAG_BACKUP_SEMANTICS,
            "CreateFileW(release directory)",
        )?;
        let executable = open_immutable_path(
            path,
            GENERIC_READ,
            FILE_ATTRIBUTE_NORMAL,
            "CreateFileW(executable)",
        )?;
        let protected_identity = file_identity(&executable)?;
        let digest = hash_immutable_file(&executable)?;
        if file_identity(&executable)? != protected_identity {
            return Err(PlatformError::IdentityMismatch(
                "approved executable changed while its protected handle was opened".to_owned(),
            ));
        }
        Ok(Self {
            executable,
            release_directory,
            path: path.to_owned(),
            digest,
            file_identity: protected_identity,
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn digest(&self) -> &str {
        &self.digest
    }

    /// Reopen the exact launch path under the same no-share policy and verify
    /// both kernel file identity and bytes.  This check is intentionally made
    /// while the child is still suspended; a path-only comparison is not a
    /// sufficient process-creation barrier.
    pub(crate) fn verify_path_barrier(&self) -> Result<(), PlatformError> {
        let candidate = open_immutable_path(
            self.path(),
            GENERIC_READ,
            FILE_ATTRIBUTE_NORMAL,
            "CreateFileW(approved executable barrier)",
        )?;
        if file_identity(&candidate)? != self.file_identity {
            return Err(PlatformError::IdentityMismatch(
                "launch path resolves to a different executable file object".to_owned(),
            ));
        }
        if hash_immutable_file(&candidate)? != self.digest {
            return Err(PlatformError::IdentityMismatch(
                "launch path executable bytes differ from the protected release".to_owned(),
            ));
        }
        Ok(())
    }
}

fn open_immutable_path(
    path: &Path,
    desired_access: u32,
    flags_and_attributes: u32,
    operation: &str,
) -> Result<OwnedHandle, PlatformError> {
    let wide_path = wide_path(path)?;
    // Share reads so the barrier and CreateProcessW can reopen the approved
    // object, while deliberately denying write and delete/rename access.
    // Holding the directory handle at the same boundary prevents the release
    // directory itself from being removed or renamed while a child is owned.
    let raw = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            desired_access,
            FILE_SHARE_READ,
            null(),
            OPEN_EXISTING,
            flags_and_attributes,
            null_mut(),
        )
    };
    OwnedHandle::new(raw, operation)
}

/// Hash one canonical executable using the same bounded read path as launch.
///
/// This helper is intended for trusted configuration/test tooling.  It does
/// not reserve the path or replace the launch-time integrity guard; callers
/// must still pass the resulting digest as an approved configuration value.
pub fn executable_sha256(path: &Path) -> Result<String, PlatformError> {
    let executable = canonicalize_executable(path)?;
    Ok(IntegrityGuards::open(&executable)?.digest().to_owned())
}

fn file_identity(file: &OwnedHandle) -> Result<FileIdentity, PlatformError> {
    let mut information =
        windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(file.raw(), &raw mut information) } == 0 {
        return Err(last_error("GetFileInformationByHandle(executable)"));
    }
    Ok(FileIdentity {
        volume_serial: information.dwVolumeSerialNumber,
        file_index: (u64::from(information.nFileIndexHigh) << 32)
            | u64::from(information.nFileIndexLow),
        size: (u64::from(information.nFileSizeHigh) << 32) | u64::from(information.nFileSizeLow),
    })
}

fn hash_immutable_file(file: &OwnedHandle) -> Result<String, PlatformError> {
    let mut file_size = 0_i64;
    let ok = unsafe { GetFileSizeEx(file.raw(), &raw mut file_size) };
    if ok == 0 {
        return Err(last_error("GetFileSizeEx(immutable executable)"));
    }
    if file_size < 0 {
        return Err(PlatformError::Unavailable(
            "immutable executable has a negative file size".to_owned(),
        ));
    }
    let expected_size = u64::try_from(file_size)
        .map_err(|_| PlatformError::Invalid("immutable executable size overflow".to_owned()))?;
    if expected_size > MAX_HASH_BYTES {
        return Err(PlatformError::Invalid(
            "immutable executable exceeds the hash size bound".to_owned(),
        ));
    }
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; HASH_READ_BYTES];
    let mut total = 0_u64;
    while total < expected_size {
        let remaining = expected_size.saturating_sub(total);
        let count = usize::try_from(remaining.min(u64::try_from(buffer.len()).map_err(|_| {
            PlatformError::Invalid("immutable hash buffer size overflow".to_owned())
        })?))
        .map_err(|_| PlatformError::Invalid("immutable hash read size overflow".to_owned()))?;
        let count = u32::try_from(count).map_err(|_| {
            PlatformError::Invalid("immutable hash read exceeds Win32 bounds".to_owned())
        })?;
        let mut read = 0_u32;
        let ok = unsafe {
            ReadFile(
                file.raw(),
                buffer.as_mut_ptr().cast(),
                count,
                &raw mut read,
                null_mut(),
            )
        };
        if ok == 0 {
            return Err(last_error("ReadFile(immutable executable)"));
        }
        if read == 0 || read > count {
            return Err(PlatformError::Unavailable(
                "immutable executable changed while it was being hashed".to_owned(),
            ));
        }
        digest.update(
            &buffer[..usize::try_from(read)
                .map_err(|_| PlatformError::Invalid("immutable hash count overflow".to_owned()))?],
        );
        total = total.saturating_add(u64::from(read));
    }
    let mut final_size = 0_i64;
    let ok = unsafe { GetFileSizeEx(file.raw(), &raw mut final_size) };
    if ok == 0 {
        return Err(last_error("GetFileSizeEx(immutable executable final)"));
    }
    if final_size < 0 || u64::try_from(final_size).ok() != Some(expected_size) {
        return Err(PlatformError::IdentityMismatch(
            "immutable executable changed while it was being hashed".to_owned(),
        ));
    }
    Ok(digest.hex())
}

#[derive(Clone, Debug)]
pub(crate) struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffered: usize,
    length_bits: u64,
}

impl Sha256 {
    pub(crate) fn new() -> Self {
        Self {
            state: [
                0x6a09_e667,
                0xbb67_ae85,
                0x3c6e_f372,
                0xa54f_f53a,
                0x510e_527f,
                0x9b05_688c,
                0x1f83_d9ab,
                0x5be0_cd19,
            ],
            buffer: [0; 64],
            buffered: 0,
            length_bits: 0,
        }
    }

    pub(crate) fn update(&mut self, mut input: &[u8]) {
        self.length_bits = self.length_bits.wrapping_add(
            u64::try_from(input.len())
                .unwrap_or(u64::MAX)
                .wrapping_mul(8),
        );
        if self.buffered != 0 {
            let needed = 64 - self.buffered;
            if input.len() < needed {
                self.buffer[self.buffered..self.buffered + input.len()].copy_from_slice(input);
                self.buffered += input.len();
                return;
            }
            self.buffer[self.buffered..].copy_from_slice(&input[..needed]);
            let block = self.buffer;
            self.compress(&block);
            self.buffered = 0;
            input = &input[needed..];
        }
        while input.len() >= 64 {
            self.compress(&input[..64]);
            input = &input[64..];
        }
        self.buffer[..input.len()].copy_from_slice(input);
        self.buffered = input.len();
    }

    fn finalize(mut self) -> [u8; 32] {
        self.buffer[self.buffered] = 0x80;
        self.buffered += 1;
        if self.buffered > 56 {
            self.buffer[self.buffered..].fill(0);
            let block = self.buffer;
            self.compress(&block);
            self.buffered = 0;
        }
        self.buffer[self.buffered..56].fill(0);
        self.buffer[56..].copy_from_slice(&self.length_bits.to_be_bytes());
        let block = self.buffer;
        self.compress(&block);
        let mut result = [0_u8; 32];
        for (index, word) in self.state.iter().enumerate() {
            result[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        result
    }

    fn compress(&mut self, block: &[u8]) {
        let mut words = [0_u32; 64];
        for (index, word) in words.iter_mut().enumerate().take(16) {
            let offset = index * 4;
            *word = u32::from_be_bytes([
                block[offset],
                block[offset + 1],
                block[offset + 2],
                block[offset + 3],
            ]);
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }
        let mut state = self.state;
        for index in 0..64 {
            let choice = (state[4] & state[5]) ^ ((!state[4]) & state[6]);
            let majority = (state[0] & state[1]) ^ (state[0] & state[2]) ^ (state[1] & state[2]);
            let sigma0 =
                state[0].rotate_right(2) ^ state[0].rotate_right(13) ^ state[0].rotate_right(22);
            let sigma1 =
                state[4].rotate_right(6) ^ state[4].rotate_right(11) ^ state[4].rotate_right(25);
            let temp1 = state[7]
                .wrapping_add(sigma1)
                .wrapping_add(choice)
                .wrapping_add(SHA256_K[index])
                .wrapping_add(words[index]);
            let temp2 = sigma0.wrapping_add(majority);
            state[7] = state[6];
            state[6] = state[5];
            state[5] = state[4];
            state[4] = state[3].wrapping_add(temp1);
            state[3] = state[2];
            state[2] = state[1];
            state[1] = state[0];
            state[0] = temp1.wrapping_add(temp2);
        }
        for (slot, value) in self.state.iter_mut().zip(state) {
            *slot = slot.wrapping_add(value);
        }
    }
}

impl Sha256 {
    pub(crate) fn hex(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let digest = self.clone().finalize();
        let mut result = String::with_capacity(digest.len().saturating_mul(2));
        for byte in digest {
            result.push(char::from(HEX[usize::from(byte >> 4)]));
            result.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        result
    }
}

pub(crate) fn canonicalize_executable(path: &Path) -> Result<PathBuf, PlatformError> {
    if !path.is_absolute() {
        return Err(PlatformError::Invalid(
            "Windows executable must be absolute".to_owned(),
        ));
    }
    let canonical = std::fs::canonicalize(path)
        .map_err(|error| PlatformError::Io(format!("executable path: {error}")))?;
    if !canonical.is_file() {
        return Err(PlatformError::Invalid(
            "Windows executable is not a regular file".to_owned(),
        ));
    }
    Ok(canonical)
}
