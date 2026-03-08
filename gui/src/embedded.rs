// Auto-generated embed manifest is included from OUT_DIR
include!(concat!(env!("OUT_DIR"), "/embed_manifest.rs"));

/// 将内嵌的 ClamAV 文件释放到指定目录。
/// 支持子目录（如 database/main.cvd → clamav_dir/database/main.cvd）。
/// 仅释放目标目录中不存在的文件。
pub fn extract_embedded_binaries(clamav_dir: &std::path::Path) {
    if EMBEDDED_FILES.is_empty() {
        return;
    }

    let _ = std::fs::create_dir_all(clamav_dir);

    for (rel_path, data) in EMBEDDED_FILES {
        let dest = clamav_dir.join(rel_path);
        if !dest.exists() {
            if let Some(parent) = dest.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::write(&dest, data);
        }
    }
}

/// 检查是否包含内嵌的 ClamAV 二进制文件
#[allow(dead_code)]
pub fn has_embedded_binaries() -> bool {
    !EMBEDDED_FILES.is_empty()
}

/// 内嵌的 ClamAV 代码签名验证证书
const CLAMAV_CRT: &[u8] = include_bytes!("../../certs/clamav.crt");

/// 将内嵌的证书释放到 clamav_dir/certs/ 目录
pub fn extract_certs(clamav_dir: &std::path::Path) {
    let certs_dir = clamav_dir.join("certs");
    let _ = std::fs::create_dir_all(&certs_dir);
    let dest = certs_dir.join("clamav.crt");
    if !dest.exists() {
        let _ = std::fs::write(&dest, CLAMAV_CRT);
    }
}
