//! Journal, file, and declarative address-set event sources.

use eris_config::{Source, StartPosition};
use eris_core::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncSeekExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Checkpoint {
    Journal {
        cursor: String,
        realtime_micros: u64,
    },
    File {
        device: u64,
        inode: u64,
        offset: u64,
        #[serde(default)]
        generation: u64,
        #[serde(default)]
        tail: Vec<u8>,
    },
    AddressSet {
        device: u64,
        inode: u64,
        modified_nanos: u64,
        size: u64,
        offset: u64,
    },
    Listener {
        sequence: u64,
    },
}

#[derive(Debug)]
pub struct SourceRecord {
    pub source: String,
    pub id: String,
    pub payload: String,
    pub correlation: Option<String>,
    pub observed_at: u64,
    pub checkpoint: Checkpoint,
    pub oversized: bool,
}

pub async fn run(
    name: String,
    source: Source,
    journalctl_path: PathBuf,
    checkpoint: Option<Checkpoint>,
    sender: mpsc::Sender<SourceRecord>,
    ready: Arc<AtomicBool>,
    shutdown: CancellationToken,
) -> Result<()> {
    ready.store(false, Ordering::Release);
    match source {
        Source::Journal {
            match_groups,
            start,
            max_entry_bytes,
        } => {
            run_journal(
                name,
                journalctl_path,
                match_groups,
                start,
                max_entry_bytes,
                checkpoint,
                sender,
                ready,
                shutdown,
            )
            .await
        }
        Source::File {
            path,
            start,
            poll_interval_ms,
            max_line_bytes,
        } => {
            run_file(
                name,
                path,
                start,
                poll_interval_ms,
                max_line_bytes,
                checkpoint,
                sender,
                ready,
                shutdown,
            )
            .await
        }
        Source::AddressSet { path } => {
            run_address_set(name, path, checkpoint, sender, ready, shutdown).await
        }
        Source::Listener { .. } => {
            ready.store(true, Ordering::Release);
            Ok(())
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_journal(
    name: String,
    journalctl_path: PathBuf,
    match_groups: Vec<BTreeMap<String, String>>,
    start: StartPosition,
    max_entry_bytes: usize,
    checkpoint: Option<Checkpoint>,
    sender: mpsc::Sender<SourceRecord>,
    ready: Arc<AtomicBool>,
    shutdown: CancellationToken,
) -> Result<()> {
    let mut command = Command::new(journalctl_path);
    command.args([
        "--system",
        "--follow",
        "--no-pager",
        "--quiet",
        "--output=json-seq",
        "--output-fields=MESSAGE,__CURSOR,__REALTIME_TIMESTAMP,_BOOT_ID,_PID,SYSLOG_PID",
    ]);
    match checkpoint {
        Some(Checkpoint::Journal {
            realtime_micros, ..
        }) => {
            command.arg(format!(
                "--since=@{}.{:06}",
                realtime_micros / 1_000_000,
                realtime_micros % 1_000_000
            ));
        }
        _ if start == StartPosition::End => {
            command.arg("--lines=0");
        }
        _ => {
            command.arg("--lines=all");
        }
    }
    for (index, group) in match_groups.iter().enumerate() {
        if index != 0 {
            command.arg("+");
        }
        command.args(
            group
                .iter()
                .map(|(field, value)| format!("{field}={value}")),
        );
    }
    command.stdout(std::process::Stdio::piped());
    let mut child = command.spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error::Io(std::io::Error::other("journalctl stdout was not piped")))?;
    let mut reader = BufReader::new(stdout);
    ready.store(true, Ordering::Release);

    loop {
        tokio::select! {
            () = shutdown.cancelled() => {
                let _ = child.kill().await;
                return Ok(());
            }
            line = read_bounded_line(&mut reader, max_entry_bytes) => {
                let Some((line, oversized, _)) = line? else {
                    let status = child.wait().await?;
                    return Err(Error::Io(std::io::Error::other(format!(
                        "journalctl source {name} exited with {status}"
                    ))));
                };
                if oversized {
                    continue;
                }
                let line = std::str::from_utf8(&line)
                    .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?
                    .trim_start_matches('\u{1e}');
                let Ok(value) = serde_json::from_str::<Value>(line) else {
                    continue;
                };
                let Some(cursor) = value.get("__CURSOR").and_then(Value::as_str) else {
                    continue;
                };
                let realtime_micros = value
                    .get("__REALTIME_TIMESTAMP")
                    .and_then(json_u64)
                    .unwrap_or_else(|| now().saturating_mul(1_000_000));
                let payload = value
                    .get("MESSAGE")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                let pid = value
                    .get("_PID")
                    .or_else(|| value.get("SYSLOG_PID"))
                    .and_then(json_text);
                let correlation = pid.map(|pid| {
                    let boot = value
                        .get("_BOOT_ID")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown-boot");
                    format!("{boot}:{pid}")
                });
                sender
                    .send(SourceRecord {
                        source: name.clone(),
                        id: cursor.to_owned(),
                        payload,
                        correlation,
                        observed_at: realtime_micros / 1_000_000,
                        checkpoint: Checkpoint::Journal {
                            cursor: cursor.to_owned(),
                            realtime_micros,
                        },
                        oversized: false,
                    })
                    .await
                    .map_err(|_| Error::Io(std::io::Error::other("defense event receiver stopped")))?;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_file(
    name: String,
    path: PathBuf,
    start: StartPosition,
    poll_interval_ms: u64,
    max_line_bytes: usize,
    checkpoint: Option<Checkpoint>,
    sender: mpsc::Sender<SourceRecord>,
    ready: Arc<AtomicBool>,
    shutdown: CancellationToken,
) -> Result<()> {
    let poll = Duration::from_millis(poll_interval_ms);
    let mut initial = checkpoint.is_none();
    let mut resume = match checkpoint {
        Some(Checkpoint::File {
            device,
            inode,
            offset,
            generation,
            tail,
        }) => Some((device, inode, offset, generation, tail)),
        _ => None,
    };

    loop {
        let file = match File::open(&path).await {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                ready.store(false, Ordering::Release);
                if !wait(&shutdown, poll).await {
                    return Ok(());
                }
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        ready.store(true, Ordering::Release);
        let metadata = file.metadata().await?;
        let identity = (metadata.dev(), metadata.ino());
        let resumed = resume.take();
        let prior_generation = resumed.as_ref().map_or(0, |value| value.3);
        let (offset, generation, mut tail) = match resumed {
            Some((device, inode, offset, generation, tail))
                if (device, inode) == identity
                    && offset <= metadata.len()
                    && (tail.is_empty() || file_tail_matches(&path, offset, &tail).await?) =>
            {
                let tail = if tail.is_empty() {
                    read_file_tail(&path, offset).await?
                } else {
                    tail
                };
                (offset, generation, tail)
            }
            _ if initial && start == StartPosition::End => {
                let offset = metadata.len();
                (
                    offset,
                    prior_generation,
                    read_file_tail(&path, offset).await?,
                )
            }
            _ => (0, prior_generation.saturating_add(1), Vec::new()),
        };
        initial = false;
        let mut reader = BufReader::new(file);
        reader.seek(std::io::SeekFrom::Start(offset)).await?;
        let mut committed = offset;
        let mut pending = Vec::new();

        loop {
            let remaining = max_line_bytes
                .saturating_add(1)
                .saturating_sub(pending.len());
            let read = (&mut reader)
                .take(remaining.max(1) as u64)
                .read_until(b'\n', &mut pending)
                .await?;
            if read == 0 {
                let current = tokio::fs::metadata(&path).await.ok();
                let replaced = current
                    .as_ref()
                    .is_none_or(|value| (value.dev(), value.ino()) != identity);
                let truncated = current
                    .as_ref()
                    .is_some_and(|value| value.len() < committed);
                let overwritten =
                    !replaced && !truncated && !file_tail_matches(&path, committed, &tail).await?;
                if replaced || truncated || overwritten {
                    if !pending.is_empty() {
                        push_tail(&mut tail, &pending);
                        committed = committed.saturating_add(pending.len() as u64);
                        send_file_record(
                            &name,
                            &sender,
                            identity,
                            generation,
                            committed,
                            tail.clone(),
                            String::new(),
                            true,
                        )
                        .await?;
                    }
                    resume = Some((
                        current.as_ref().map_or(0, |value| value.dev()),
                        current.as_ref().map_or(0, |value| value.ino()),
                        0,
                        generation.saturating_add(1),
                        Vec::new(),
                    ));
                    break;
                }
                if !wait(&shutdown, poll).await {
                    return Ok(());
                }
                continue;
            }

            if pending.len() > max_line_bytes {
                let mut consumed = pending.len() as u64;
                let ended = pending.ends_with(b"\n");
                push_tail(&mut tail, &pending);
                pending.clear();
                if !ended {
                    consumed = consumed
                        .saturating_add(drain_line_with_tail(&mut reader, &mut tail).await?);
                }
                committed = committed.saturating_add(consumed);
                send_file_record(
                    &name,
                    &sender,
                    identity,
                    generation,
                    committed,
                    tail.clone(),
                    String::new(),
                    true,
                )
                .await?;
                continue;
            }
            if !pending.ends_with(b"\n") {
                continue;
            }

            committed = committed.saturating_add(pending.len() as u64);
            push_tail(&mut tail, &pending);
            let payload = String::from_utf8_lossy(&pending)
                .trim_end_matches(['\r', '\n'])
                .to_owned();
            pending.clear();
            send_file_record(
                &name,
                &sender,
                identity,
                generation,
                committed,
                tail.clone(),
                payload,
                false,
            )
            .await?;
        }
    }
}

async fn send_file_record(
    name: &str,
    sender: &mpsc::Sender<SourceRecord>,
    identity: (u64, u64),
    generation: u64,
    offset: u64,
    tail: Vec<u8>,
    payload: String,
    oversized: bool,
) -> Result<()> {
    sender
        .send(SourceRecord {
            source: name.to_owned(),
            id: format!("{}:{}:{generation}:{offset}", identity.0, identity.1),
            payload,
            correlation: None,
            observed_at: now(),
            checkpoint: Checkpoint::File {
                device: identity.0,
                inode: identity.1,
                offset,
                generation,
                tail,
            },
            oversized,
        })
        .await
        .map_err(|_| Error::Io(std::io::Error::other("defense event receiver stopped")))
}

const FILE_TAIL_BYTES: usize = 64;

fn push_tail(tail: &mut Vec<u8>, bytes: &[u8]) {
    if bytes.len() >= FILE_TAIL_BYTES {
        tail.clear();
        tail.extend_from_slice(&bytes[bytes.len() - FILE_TAIL_BYTES..]);
        return;
    }
    let overflow = tail
        .len()
        .saturating_add(bytes.len())
        .saturating_sub(FILE_TAIL_BYTES);
    if overflow != 0 {
        tail.drain(..overflow);
    }
    tail.extend_from_slice(bytes);
}

async fn read_file_tail(path: &PathBuf, offset: u64) -> std::io::Result<Vec<u8>> {
    let length = offset.min(FILE_TAIL_BYTES as u64);
    if length == 0 {
        return Ok(Vec::new());
    }
    let mut file = File::open(path).await?;
    file.seek(std::io::SeekFrom::Start(offset - length)).await?;
    let mut tail = Vec::with_capacity(length as usize);
    (&mut file).take(length).read_to_end(&mut tail).await?;
    Ok(tail)
}

async fn file_tail_matches(path: &PathBuf, offset: u64, expected: &[u8]) -> std::io::Result<bool> {
    Ok(read_file_tail(path, offset).await? == expected)
}

async fn drain_line_with_tail<R>(
    reader: &mut BufReader<R>,
    tail: &mut Vec<u8>,
) -> std::io::Result<u64>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut total = 0u64;
    loop {
        let buffer = reader.fill_buf().await?;
        if buffer.is_empty() {
            return Ok(total);
        }
        let length = buffer
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(buffer.len(), |index| index + 1);
        let ended = buffer.get(length.saturating_sub(1)) == Some(&b'\n');
        let exhausted = length == buffer.len();
        push_tail(tail, &buffer[..length]);
        reader.consume(length);
        total = total.saturating_add(length as u64);
        if !exhausted || ended {
            return Ok(total);
        }
    }
}

async fn drain_line<R>(reader: &mut BufReader<R>) -> std::io::Result<u64>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut total = 0u64;
    loop {
        let buffer = reader.fill_buf().await?;
        if buffer.is_empty() {
            return Ok(total);
        }
        let length = buffer
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(buffer.len(), |index| index + 1);
        let ended = buffer.get(length.saturating_sub(1)) == Some(&b'\n');
        let exhausted = length == buffer.len();
        reader.consume(length);
        total = total.saturating_add(length as u64);
        if !exhausted || ended {
            return Ok(total);
        }
    }
}

async fn read_bounded_line<R>(
    reader: &mut BufReader<R>,
    limit: usize,
) -> std::io::Result<Option<(Vec<u8>, bool, u64)>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut line = Vec::new();
    let read = (&mut *reader)
        .take(limit.saturating_add(1) as u64)
        .read_until(b'\n', &mut line)
        .await?;
    if read == 0 {
        return Ok(None);
    }
    let oversized = line.len() > limit;
    let mut consumed = line.len() as u64;
    if oversized && !line.ends_with(b"\n") {
        consumed = consumed.saturating_add(drain_line(reader).await?);
    }
    Ok(Some((line, oversized, consumed)))
}

async fn run_address_set(
    name: String,
    path: PathBuf,
    checkpoint: Option<Checkpoint>,
    sender: mpsc::Sender<SourceRecord>,
    ready: Arc<AtomicBool>,
    shutdown: CancellationToken,
) -> Result<()> {
    const MAX_CIDR_LINE_BYTES: usize = 4096;
    let mut resume = match checkpoint {
        Some(Checkpoint::AddressSet {
            device,
            inode,
            modified_nanos,
            size,
            offset,
        }) => Some((device, inode, modified_nanos, size, offset)),
        _ => None,
    };
    loop {
        let metadata = tokio::fs::metadata(&path).await?;
        let modified_nanos = metadata
            .modified()?
            .duration_since(UNIX_EPOCH)
            .map(|duration| u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX))
            .unwrap_or_default();
        let identity = (
            metadata.dev(),
            metadata.ino(),
            modified_nanos,
            metadata.len(),
        );
        let checkpoint = resume.take();
        let same_identity = checkpoint.is_some_and(|(device, inode, modified, size, _)| {
            (device, inode, modified, size) == identity
        });
        let offset = checkpoint
            .filter(|(device, inode, modified, size, _)| {
                (*device, *inode, *modified, *size) == identity
            })
            .map_or(0, |(_, _, _, _, offset)| offset.min(metadata.len()));
        if offset < metadata.len() || !same_identity {
            let mut reader = BufReader::new(File::open(&path).await?);
            reader.seek(std::io::SeekFrom::Start(offset)).await?;
            let mut committed = offset;
            let mut emitted = false;
            while let Some((line, oversized, consumed)) =
                read_bounded_line(&mut reader, MAX_CIDR_LINE_BYTES).await?
            {
                committed = committed.saturating_add(consumed);
                let payload = String::from_utf8_lossy(&line)
                    .trim_end_matches(['\r', '\n'])
                    .split('#')
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .to_owned();
                sender
                    .send(SourceRecord {
                        source: name.clone(),
                        id: format!(
                            "{}:{modified_nanos}:{}:{committed}",
                            path.display(),
                            metadata.len()
                        ),
                        payload,
                        correlation: None,
                        observed_at: now(),
                        checkpoint: Checkpoint::AddressSet {
                            device: metadata.dev(),
                            inode: metadata.ino(),
                            modified_nanos,
                            size: metadata.len(),
                            offset: committed,
                        },
                        oversized: oversized || line.is_empty(),
                    })
                    .await
                    .map_err(|_| {
                        Error::Io(std::io::Error::other("defense event receiver stopped"))
                    })?;
                emitted = true;
            }
            if !emitted {
                sender
                    .send(SourceRecord {
                        source: name.clone(),
                        id: format!("{}:{modified_nanos}:empty", path.display()),
                        payload: String::new(),
                        correlation: None,
                        observed_at: now(),
                        checkpoint: Checkpoint::AddressSet {
                            device: metadata.dev(),
                            inode: metadata.ino(),
                            modified_nanos,
                            size: metadata.len(),
                            offset: metadata.len(),
                        },
                        oversized: true,
                    })
                    .await
                    .map_err(|_| {
                        Error::Io(std::io::Error::other("defense event receiver stopped"))
                    })?;
            }
        }
        ready.store(true, Ordering::Release);
        resume = Some((
            metadata.dev(),
            metadata.ino(),
            modified_nanos,
            metadata.len(),
            metadata.len(),
        ));
        if !wait(&shutdown, Duration::from_secs(5)).await {
            return Ok(());
        }
    }
}

async fn wait(shutdown: &CancellationToken, duration: Duration) -> bool {
    tokio::select! {
        () = shutdown.cancelled() => false,
        () = tokio::time::sleep(duration) => true,
    }
}

fn json_u64(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
}

fn json_text(value: &Value) -> Option<String> {
    value
        .as_str()
        .map(str::to_owned)
        .or_else(|| value.as_u64().map(|value| value.to_string()))
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    static NEXT_FILE: AtomicUsize = AtomicUsize::new(0);

    #[tokio::test]
    async fn copytruncate_restarts_at_zero_with_a_new_generation() {
        let path = std::env::temp_dir().join(format!(
            "eris-source-{}-{}.log",
            std::process::id(),
            NEXT_FILE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, b"one\n").unwrap();
        let (sender, mut receiver) = mpsc::channel(8);
        let ready = Arc::new(AtomicBool::new(false));
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(run_file(
            "test".into(),
            path.clone(),
            StartPosition::Beginning,
            10,
            1024,
            None,
            sender,
            ready,
            shutdown.clone(),
        ));

        let first = tokio::time::timeout(Duration::from_secs(2), receiver.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first.payload, "one");
        std::fs::write(&path, b"two\n").unwrap();
        let second = tokio::time::timeout(Duration::from_secs(2), receiver.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(second.payload, "two");
        assert_ne!(first.id, second.id);

        shutdown.cancel();
        task.await.unwrap().unwrap();
        let _ = std::fs::remove_file(path);
    }
}
