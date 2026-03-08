// Auto-generated embed manifest is included from OUT_DIR
include!(concat!(env!("OUT_DIR"), "/embed_manifest.rs"));

/// 将内嵌的 ClamAV 二进制文件释放到指定目录。
/// 仅释放目标目录中不存在的文件。
pub fn extract_embedded_binaries(clamav_dir: &std::path::Path) {
    if EMBEDDED_FILES.is_empty() {
        return;
    }

    let _ = std::fs::create_dir_all(clamav_dir);

    for (filename, data) in EMBEDDED_FILES {
        let dest = clamav_dir.join(filename);
        if !dest.exists() {
            let _ = std::fs::write(&dest, data);
        }
    }
}

/// 检查是否包含内嵌的 ClamAV 二进制文件
#[allow(dead_code)]
pub fn has_embedded_binaries() -> bool {
    !EMBEDDED_FILES.is_empty()
}
