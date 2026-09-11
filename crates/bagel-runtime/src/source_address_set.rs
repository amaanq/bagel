use std::{
   os::unix::fs::MetadataExt,
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
      UNIX_EPOCH,
   },
};

use bagel_core::{
   Error,
   Result,
};
use tokio::{
   fs::File,
   io::{
      AsyncSeekExt,
      BufReader,
   },
   sync::mpsc,
};
use tokio_util::sync::CancellationToken;

use crate::source::{
   Checkpoint,
   SourceRecord,
   now,
   read_bounded_line,
   wait,
};

pub async fn run(
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
               .map_err(|_| Error::Io(std::io::Error::other("defense event receiver stopped")))?;
            emitted = true;
         }
         if !emitted {
            sender
               .send(SourceRecord {
                  source:      name.clone(),
                  id:          format!("{}:{modified_nanos}:empty", path.display()),
                  payload:     String::new(),
                  correlation: None,
                  observed_at: now(),
                  checkpoint:  Checkpoint::AddressSet {
                     device: metadata.dev(),
                     inode: metadata.ino(),
                     modified_nanos,
                     size: metadata.len(),
                     offset: metadata.len(),
                  },
                  oversized:   true,
               })
               .await
               .map_err(|_| Error::Io(std::io::Error::other("defense event receiver stopped")))?;
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
