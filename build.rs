use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    // Only perform driver bundling on Windows
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "windows" {
        return;
    }

    let out_dir = env::var("OUT_DIR").unwrap();
    // OUT_DIR is typically: target/{profile}/build/{package}-{hash}/out
    // We want to copy DLL and SYS files to target/{profile}/
    let out_path = PathBuf::from(out_dir);
    let target_dir = out_path
        .parent() // build/{pkg}
        .and_then(|p| p.parent()) // build/
        .and_then(|p| p.parent()); // target/{profile}

    let target_dir = match target_dir {
        Some(d) => d,
        None => return,
    };

    // Potential source locations for WinDivert driver binaries
    let home = env::var("USERPROFILE").unwrap_or_default();
    let candidates = vec![
        PathBuf::from("target/release"),
        PathBuf::from(format!(
            "{}\\anaconda3\\Lib\\site-packages\\pydivert\\windivert_dll",
            home
        )),
        PathBuf::from(format!(
            "{}\\AppData\\Roaming\\Python\\Python313\\site-packages\\pydivert\\windivert_dll",
            home
        )),
        PathBuf::from("."),
    ];

    let files_to_copy = [
        ("WinDivert64.dll", "WinDivert.dll"),
        ("WinDivert64.dll", "WinDivert64.dll"),
        ("WinDivert64.sys", "WinDivert.sys"),
        ("WinDivert64.sys", "WinDivert64.sys"),
    ];

    for src_dir in candidates {
        if !src_dir.exists() {
            continue;
        }

        let mut copied = false;
        for &(src_name, dst_name) in &files_to_copy {
            let src_file = src_dir.join(src_name);
            if src_file.exists() {
                let dst_file = target_dir.join(dst_name);
                if let Err(e) = fs::copy(&src_file, &dst_file) {
                    // Ignore if destination is locked/already identical
                    let _ = e;
                }
                copied = true;
            }
        }

        if copied {
            break;
        }
    }
}
