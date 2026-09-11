use std::{
   collections::BTreeMap,
   path::PathBuf,
   sync::atomic::Ordering,
};

use bagel_config::StartPosition;
use bagel_core::{
   Error,
   Result,
};
use serde_json::Value;
use tokio::{
   io::BufReader,
   process::Command,
};

use crate::source::{
   Checkpoint,
   SourceCtx,
   SourceRecord,
   json_text,
   json_u64,
   now,
   read_bounded_line,
};

pub async fn run(
   ctx: SourceCtx,
   journalctl_path: PathBuf,
   match_groups: Vec<BTreeMap<String, String>>,
   start: StartPosition,
   max_entry_bytes: usize,
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
   match ctx.checkpoint {
      Some(Checkpoint::Journal {
         realtime_micros, ..
      }) => {
         command.arg(format!(
            "--since=@{}.{:06}",
            realtime_micros / 1_000_000,
            realtime_micros % 1_000_000
         ));
      },
      _ if start == StartPosition::End => {
         command.arg("--lines=0");
      },
      _ => {
         command.arg("--lines=all");
      },
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
   ctx.ready.store(true, Ordering::Release);

   loop {
      tokio::select! {
          () = ctx.shutdown.cancelled() => {
              let _ = child.kill().await;
              return Ok(());
          }
          line = read_bounded_line(&mut reader, max_entry_bytes) => {
              let Some((line, oversized, _)) = line? else {
                  let status = child.wait().await?;
                  return Err(Error::Io(std::io::Error::other(format!(
                      "journalctl source {} exited with {status}",
                      ctx.name
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
              ctx.sender
                  .send(SourceRecord {
                      source: ctx.name.clone(),
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
