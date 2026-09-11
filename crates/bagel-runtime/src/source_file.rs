use std::{
   os::unix::fs::MetadataExt,
   path::PathBuf,
   sync::atomic::Ordering,
   time::Duration,
};

use bagel_config::StartPosition;
use bagel_core::Result;
use tokio::{
   fs::File,
   io::{
      AsyncBufReadExt,
      AsyncReadExt,
      AsyncSeekExt,
      BufReader,
   },
};

use crate::source::{
   Checkpoint,
   FileEmit,
   SourceCtx,
   drain_line,
   file_tail_matches,
   push_tail,
   read_file_tail,
   send_file_record,
   wait,
};

pub async fn run(
   ctx: SourceCtx,
   path: PathBuf,
   start: StartPosition,
   poll_interval_ms: u64,
   max_line_bytes: usize,
) -> Result<()> {
   let poll = Duration::from_millis(poll_interval_ms);
   let mut initial = ctx.checkpoint.is_none();
   let mut resume = match ctx.checkpoint {
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
            ctx.ready.store(false, Ordering::Release);
            if !wait(&ctx.shutdown, poll).await {
               return Ok(());
            }
            continue;
         },
         Err(error) => return Err(error.into()),
      };
      ctx.ready.store(true, Ordering::Release);
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
         },
         _ if initial && start == StartPosition::End => {
            let offset = metadata.len();
            (
               offset,
               prior_generation,
               read_file_tail(&path, offset).await?,
            )
         },
         _ => (0, prior_generation.saturating_add(1), Vec::new()),
      };
      initial = false;
      let mut reader = BufReader::new(file);
      reader.seek(std::io::SeekFrom::Start(offset)).await?;
      let mut committed = offset;
      let mut pending = Vec::new();
      let emit = FileEmit {
         name: ctx.name.clone(),
         sender: ctx.sender.clone(),
         identity,
         generation,
      };

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
                  send_file_record(&emit, committed, tail.clone(), String::new(), true).await?;
               }
               resume = Some((
                  current.as_ref().map_or(0, MetadataExt::dev),
                  current.as_ref().map_or(0, MetadataExt::ino),
                  0,
                  generation.saturating_add(1),
                  Vec::new(),
               ));
               break;
            }
            if !wait(&ctx.shutdown, poll).await {
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
               consumed = consumed.saturating_add(drain_line(&mut reader, Some(&mut tail)).await?);
            }
            committed = committed.saturating_add(consumed);
            send_file_record(&emit, committed, tail.clone(), String::new(), true).await?;
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
         send_file_record(&emit, committed, tail.clone(), payload, false).await?;
      }
   }
}
