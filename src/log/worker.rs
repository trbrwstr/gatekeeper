use tokio::fs::{self, File, OpenOptions};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

/// Size at which the audit log is rotated to `<path>.1` so it cannot grow
/// unbounded and fill the disk.
const MAX_LOG_BYTES: u64 = 50 * 1024 * 1024;

async fn open_log(path: &str) -> std::io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path).await
}

pub async fn start(mut rx: mpsc::Receiver<String>, log_path: String) {
    let mut file = match open_log(&log_path).await {
        Ok(f) => f,
        Err(e) => {
            tracing::error!("failed to open audit log file: {}", e);
            return;
        }
    };
    let mut size = fs::metadata(&log_path).await.map(|m| m.len()).unwrap_or(0);

    while let Some(line) = rx.recv().await {
        let needed = line.len() as u64 + 1;

        if size + needed > MAX_LOG_BYTES {
            if let Err(e) = file.flush().await {
                tracing::error!("failed to flush audit log before rotation: {}", e);
            }
            match fs::rename(&log_path, format!("{}.1", log_path)).await {
                Ok(()) => match open_log(&log_path).await {
                    Ok(f) => {
                        file = f;
                        size = 0;
                    }
                    Err(e) => {
                        tracing::error!("failed to reopen audit log after rotation: {}", e);
                        return;
                    }
                },
                Err(e) => tracing::error!("failed to rotate audit log: {}", e),
            }
        }

        if let Err(e) = file.write_all(line.as_bytes()).await {
            tracing::error!("failed to write audit log: {}", e);
        }
        if let Err(e) = file.write_all(b"\n").await {
            tracing::error!("failed to write audit log newline: {}", e);
        }
        if let Err(e) = file.flush().await {
            tracing::error!("failed to flush audit log: {}", e);
        }
        size += needed;
    }
}
