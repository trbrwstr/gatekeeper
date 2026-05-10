use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

pub async fn start(mut rx: mpsc::Receiver<String>, log_path: String) {
    let mut file = match OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .await
    {
        Ok(f) => f,
        Err(e) => {
            tracing::error!("failed to open audit log file: {}", e);
            return;
        }
    };

    while let Some(line) = rx.recv().await {
        if let Err(e) = file.write_all(line.as_bytes()).await {
            tracing::error!("failed to write audit log: {}", e);
        }
        if let Err(e) = file.write_all(b"\n").await {
            tracing::error!("failed to write audit log newline: {}", e);
        }
        if let Err(e) = file.flush().await {
            tracing::error!("failed to flush audit log: {}", e);
        }
    }
}
