// Auto-generated embed manifest is included from OUT_DIR
include!(concat!(env!("OUT_DIR"), "/embed_manifest.rs"));

// Auto-generated YAMAGoya embed manifest
include!(concat!(env!("OUT_DIR"), "/yamagoya_manifest.rs"));

/// Number of ClamAV files baked into this executable.
pub fn embedded_file_count() -> usize {
    EMBEDDED_FILES.len()
}

/// Number of YAMAGoya files baked into this executable.
pub fn yamagoya_file_count() -> usize {
    YAMAGOYA_FILES.len()
}

/// Decompress a zstd stream.
fn decompress(compressed: &[u8]) -> Option<Vec<u8>> {
    zstd::decode_all(compressed).ok()
}

/// Write `data` to `dest` atomically.
///
/// Unpacking used to write straight to the destination. If the process was
/// killed (or the disk filled up) half way through, the truncated file stayed
/// on disk and the `dest.exists()` guard below meant it was *never* repaired –
/// leaving the user with a permanently broken ClamAV install. Writing to a
/// sibling temp file and renaming makes the operation all-or-nothing.
fn write_atomic(dest: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    let file_name = dest
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".to_string());
    let tmp = dest.with_file_name(format!(".{}.part", file_name));

    std::fs::write(&tmp, data)?;

    // Windows refuses to rename onto an existing file, so clear the way first.
    if dest.exists() {
        let _ = std::fs::remove_file(dest);
    }
    match std::fs::rename(&tmp, dest) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// A destination only counts as present when it is a non-empty regular file.
fn needs_extract(dest: &std::path::Path) -> bool {
    match std::fs::metadata(dest) {
        Ok(meta) => !meta.is_file() || meta.len() == 0,
        Err(_) => true,
    }
}

/// Core unpack loop shared by both manifests.
fn extract_all(
    base_dir: &std::path::Path,
    files: &[(&str, &[u8])],
    mut report: impl FnMut(&str),
) -> usize {
    let mut extracted = 0usize;

    for (rel_path, compressed_data) in files {
        let dest = base_dir.join(rel_path);
        // Always report, so callers can drive a progress bar even when the
        // file is already present.
        if needs_extract(&dest) {
            if let Some(parent) = dest.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Some(data) = decompress(compressed_data) {
                if write_atomic(&dest, &data).is_ok() {
                    extracted += 1;
                }
            }
        }
        report(rel_path);
    }

    extracted
}

/// Unpack the embedded ClamAV toolchain, reporting each file as it is handled.
pub fn extract_embedded_binaries_reporting(
    clamav_dir: &std::path::Path,
    report: impl FnMut(&str),
) -> usize {
    if EMBEDDED_FILES.is_empty() {
        return 0;
    }
    let _ = std::fs::create_dir_all(clamav_dir);
    extract_all(clamav_dir, EMBEDDED_FILES, report)
}

/// Unpack the embedded YAMAGoya binary and rules, reporting each file.
pub fn extract_yamagoya_reporting(base_dir: &std::path::Path, report: impl FnMut(&str)) -> usize {
    if YAMAGOYA_FILES.is_empty() {
        return 0;
    }
    let _ = std::fs::create_dir_all(base_dir);
    extract_all(base_dir, YAMAGOYA_FILES, report)
}

/// Whether this build carries ClamAV binaries inside the executable.
#[allow(dead_code)]
pub fn has_embedded_binaries() -> bool {
    !EMBEDDED_FILES.is_empty()
}

/// The ClamAV code-signing certificate, needed by freshclam.
const CLAMAV_CRT: &[u8] = include_bytes!("../../certs/clamav.crt");

/// Unpack the bundled code-signing certificate into `clamav_dir/certs/`.
pub fn extract_certs(clamav_dir: &std::path::Path) {
    let certs_dir = clamav_dir.join("certs");
    let _ = std::fs::create_dir_all(&certs_dir);
    let dest = certs_dir.join("clamav.crt");
    if needs_extract(&dest) {
        let _ = write_atomic(&dest, CLAMAV_CRT);
    }
}
