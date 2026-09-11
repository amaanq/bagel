//! Journal, file, and declarative address-set event sources.

use std::{
   path::PathBuf,
   sync::{
      Arc,
      atomic::{
         AtomicBool,
         Ordering,
      },
   },
   time::{
      Duration,
      SystemTime,
      UNIX_EPOCH,
   },
};

use bagel_config::Source;
use bagel_core::{
   Error,
   Result,
};
use serde::{
   Deserialize,
   Serialize,
};
use serde_json::Value;
use tokio::{
   fs::File,
   io::{
      AsyncBufReadExt,
      AsyncReadExt,
      AsyncSeekExt,
      BufReader,
   },
   sync::mpsc,
};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Checkpoint {
   Journal {
      cursor:          String,
      realtime_micros: u64,
   },
   File {
      device:     u64,
      inode:      u64,
      offset:     u64,
      #[serde(default)]
      generation: u64,
      #[serde(default)]
      tail:       Vec<u8>,
   },
   AddressSet {
      device:         u64,
      inode:          u64,
      modified_nanos: u64,
      size:           u64,
      offset:         u64,
   },
   Listener {
      sequence: u64,
   },
}

pub struct SourceRecord {
   pub source:      String,
   pub id:          String,
   pub payload:     String,
   pub correlation: Option<String>,
   pub observed_at: u64,
   pub checkpoint:  Checkpoint,
   pub oversized:   bool,
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
         crate::source_journal::run(
            SourceCtx {
               name,
               checkpoint,
               sender,
               ready,
               shutdown,
            },
            journalctl_path,
            match_groups,
            start,
            max_entry_bytes,
         )
         .await
      },
      Source::File {
         path,
         start,
         poll_interval_ms,
         max_line_bytes,
      } => {
         crate::source_file::run(
            SourceCtx {
               name,
               checkpoint,
               sender,
               ready,
               shutdown,
            },
            path,
            start,
            poll_interval_ms,
            max_line_bytes,
         )
         .await
      },
      Source::AddressSet { path } => {
         crate::source_address_set::run(name, path, checkpoint, sender, ready, shutdown).await
      },
      Source::Listener { .. } | Source::Web => {
         ready.store(true, Ordering::Release);
         Ok(())
      },
   }
}

pub(crate) struct SourceCtx {
   pub name:       String,
   pub checkpoint: Option<Checkpoint>,
   pub sender:     mpsc::Sender<SourceRecord>,
   pub ready:      Arc<AtomicBool>,
   pub shutdown:   CancellationToken,
}

pub(crate) struct FileEmit {
   pub name:       String,
   pub sender:     mpsc::Sender<SourceRecord>,
   pub identity:   (u64, u64),
   pub generation: u64,
}

pub(crate) async fn send_file_record(
   emit: &FileEmit,
   offset: u64,
   tail: Vec<u8>,
   payload: String,
   oversized: bool,
) -> Result<()> {
   emit
      .sender
      .send(SourceRecord {
         source: emit.name.clone(),
         id: format!(
            "{}:{}:{}:{offset}",
            emit.identity.0, emit.identity.1, emit.generation
         ),
         payload,
         correlation: None,
         observed_at: now(),
         checkpoint: Checkpoint::File {
            device: emit.identity.0,
            inode: emit.identity.1,
            offset,
            generation: emit.generation,
            tail,
         },
         oversized,
      })
      .await
      .map_err(|_| Error::Io(std::io::Error::other("defense event receiver stopped")))
}

const FILE_TAIL_BYTES: usize = 64;

pub(crate) fn push_tail(tail: &mut Vec<u8>, bytes: &[u8]) {
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

pub(crate) async fn read_file_tail(path: &PathBuf, offset: u64) -> std::io::Result<Vec<u8>> {
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

pub(crate) async fn file_tail_matches(
   path: &PathBuf,
   offset: u64,
   expected: &[u8],
) -> std::io::Result<bool> {
   Ok(read_file_tail(path, offset).await? == expected)
}

pub(crate) async fn drain_line<R>(
   reader: &mut BufReader<R>,
   mut tail: Option<&mut Vec<u8>>,
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
      if let Some(tail) = tail.as_deref_mut() {
         push_tail(tail, &buffer[..length]);
      }
      reader.consume(length);
      total = total.saturating_add(length as u64);
      if !exhausted || ended {
         return Ok(total);
      }
   }
}

pub(crate) async fn read_bounded_line<R>(
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
      consumed = consumed.saturating_add(drain_line(reader, None).await?);
   }
   Ok(Some((line, oversized, consumed)))
}

pub(crate) async fn wait(shutdown: &CancellationToken, duration: Duration) -> bool {
   tokio::select! {
       () = shutdown.cancelled() => false,
       () = tokio::time::sleep(duration) => true,
   }
}

pub(crate) fn json_u64(value: &Value) -> Option<u64> {
   value.as_u64().or_else(|| value.as_str()?.parse().ok())
}

pub(crate) fn json_text(value: &Value) -> Option<String> {
   value
      .as_str()
      .map(str::to_owned)
      .or_else(|| value.as_u64().map(|value| value.to_string()))
}

pub(crate) fn now() -> u64 {
   SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .map(|duration| duration.as_secs())
      .unwrap_or_default()
}

#[cfg(test)]
mod tests {
   use std::{
      sync::{
         Arc,
         atomic::{
            AtomicBool,
            AtomicUsize,
            Ordering,
         },
      },
      time::Duration,
   };

   use bagel_config::StartPosition;
   use tokio::sync::mpsc;
   use tokio_util::sync::CancellationToken;

   use crate::{
      source::SourceCtx,
      source_file,
   };

   static NEXT_FILE: AtomicUsize = AtomicUsize::new(0);

   #[tokio::test]
   async fn copytruncate_restarts_at_zero_with_a_new_generation() {
      let path = std::env::temp_dir().join(format!(
         "bagel-source-{}-{}.log",
         std::process::id(),
         NEXT_FILE.fetch_add(1, Ordering::Relaxed)
      ));
      std::fs::write(&path, b"one\n").unwrap();
      let (sender, mut receiver) = mpsc::channel(8);
      let ready = Arc::new(AtomicBool::new(false));
      let shutdown = CancellationToken::new();
      let task = tokio::spawn(source_file::run(
         SourceCtx {
            name: "test".into(),
            checkpoint: None,
            sender,
            ready,
            shutdown: shutdown.clone(),
         },
         path.clone(),
         StartPosition::Beginning,
         10,
         1024,
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
